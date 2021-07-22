module vls

import v.pref
import json
import jsonrpc
import lsp
import lsp.log
import os
import tree_sitter
import tree_sitter_v.bindings.v
import analyzer
import time

// These are the list of features available in VLS
// If the feature is experimental, the value name should have a `exp_` prefix
pub enum Feature {
	diagnostics
	formatting
	document_symbol
	workspace_symbol
	signature_help
	completion
	hover
	folding_range
	definition
}

// feature_from_str returns the Feature-enum value equivalent of the given string.
// used internally for Vls.set_features method only.
fn feature_from_str(feature_name string) ?Feature {
	match feature_name {
		'diagnostics' { return Feature.diagnostics }
		'formatting' { return Feature.formatting }
		'document_symbol' { return Feature.document_symbol }
		'workspace_symbol' { return Feature.workspace_symbol }
		'signature_help' { return Feature.signature_help }
		'completion' { return Feature.completion }
		'hover' { return Feature.hover }
		'folding_range' { return Feature.folding_range }
		'definition' { return Feature.definition }
		else { return error('feature "$feature_name" not found') }
	}
}

pub const (
	default_features_list = [
		Feature.diagnostics,
		.formatting,
		.document_symbol,
		.workspace_symbol,
		.signature_help,
		.completion,
		.hover,
		.folding_range,
		.definition,
	]
)

interface ReceiveSender {
	debug bool
	send(data string)
	receive() ?string
}

struct Vls {
mut:
	parser           &C.TSParser
	store            analyzer.Store
	status           ServerStatus = .off
	sources          map[string]File
	trees            map[string]&C.TSTree
	root_uri         lsp.DocumentUri
	is_typing        bool
	typing_ch        chan int
	enabled_features []Feature = vls.default_features_list
	capabilities     lsp.ServerCapabilities
	logger           log.Logger
	panic_count      int
	debug            bool
	// client_capabilities lsp.ClientCapabilities
pub mut:
	// TODO: replace with io.ReadWriter
	io ReceiveSender
}

pub fn new(io ReceiveSender) Vls {
	// mut tbl := ast.new_table()
	// tbl.is_fmt = false
	mut parser := tree_sitter.new_parser()
	parser.set_language(v.language)

	return Vls{
		io: io
		parser: parser
		debug: io.debug
		logger: log.new(.text)
		store: analyzer.Store{
			default_import_paths: [vlib_path, vmodules_path]
		}
	}
}

pub fn (mut ls Vls) dispatch(payload string) {
	request := json.decode(jsonrpc.Request, payload) or {
		ls.send(new_error(jsonrpc.parse_error))
		return
	}
	// The server will log a send request/notification
	// log based on the the received payload since the spec
	// doesn't indicate a way to log on the client side and
	// notify it to the server.
	//
	// Notification has no ID attached so the server can detect
	// if its a notification or a request payload by checking
	// if the ID is on the default value which is -2. (Some
	// clients such as VSCode used 0 as the first request ID
	// hence the use of a negative integer).
	if request.id == -2 {
		ls.logger.notification(payload, .send)
		ls.logger.notification(payload, .receive)
	} else {
		ls.logger.request(payload, .send)
		ls.logger.request(payload, .receive)
	}
	if ls.status == .initialized {
		match request.method {
			// not only requests but also notifications
			'initialized' {} // does nothing currently
			'shutdown' {
				// NB: Some users reported that after closing their text editors,
				// the vls process isn't properly closed at all and the editor still
				// continuously sending useless requests during the shutdown phase
				// which dramatically increases the memory. Unless there is a fix
				// or other possible alternatives, the solution for now is to
				// immediately exit when the server receives a shutdown request.
				// Freeing extra memory here
				ls.exit()
				// ls.shutdown(request.id)
			}
			'exit' {
				// ignore for the reasons stated in the above comment
			}
			'textDocument/didOpen' {
				ls.did_open(request.id, request.params)
			}
			'textDocument/didChange' {
				ls.typing_ch <- 1
				ls.did_change(request.id, request.params)
			}
			'textDocument/didClose' {
				ls.did_close(request.id, request.params)
			}
			'textDocument/formatting' {
				ls.formatting(request.id, request.params)
			}
			'textDocument/documentSymbol' {
				ls.document_symbol(request.id, request.params)
			}
			'workspace/symbol' {
				ls.workspace_symbol(request.id, request.params)
			}
			'textDocument/signatureHelp' {
				ls.signature_help(request.id, request.params)
			}
			'textDocument/completion' {
				ls.completion(request.id, request.params)
			}
			'textDocument/hover' {
				ls.hover(request.id, request.params)
			}
			'textDocument/foldingRange' {
				ls.folding_range(request.id, request.params)
			}
			'textDocument/definition' {
				ls.definition(request.id, request.params)
			}
			else {}
		}
	} else {
		match request.method {
			'exit' {
				ls.exit()
			}
			'initialize' {
				ls.initialize(request.id, request.params)
			}
			else {
				err_type := if ls.status == .shutdown {
					jsonrpc.invalid_request
				} else {
					jsonrpc.server_not_initialized
				}
				ls.send(new_error(err_type))
			}
		}
	}
}

// set_logger changes the language server's logger
pub fn (mut ls Vls) set_logger(logger log.Logger) {
	ls.logger.close()
	ls.logger = logger
}

// capabilities returns the current server capabilities
pub fn (ls Vls) capabilities() lsp.ServerCapabilities {
	return ls.capabilities
}

// features returns the current server features enabled
pub fn (ls Vls) features() []Feature {
	return ls.enabled_features
}

// status returns the current server status
pub fn (ls Vls) status() ServerStatus {
	return ls.status
}

// log_path returns the combined path of the workspace's root URI and the log file name.
fn (ls Vls) log_path() string {
	return os.join_path(ls.root_uri.path(), 'vls.log')
}

// panic generates a log report and exits the language server.
fn (mut ls Vls) panic(message string) {
	ls.panic_count++

	// NB: Would 2 be enough to exit?
	if ls.panic_count == 2 {
		log_path := ls.log_path()
		ls.logger.set_logpath(log_path)
		ls.show_message('VLS Panic: ${message}. Log saved to ${os.real_path(log_path)}. Please refer to https://github.com/vlang/vls#error-reporting for more details.',
			.error)
		ls.logger.close()
		ls.exit()
	} else {
		ls.log_message('VLS: An error occurred. Message: $message', .error)
	}
}

fn (mut ls Vls) send<T>(data T) {
	str := json.encode(data)
	ls.logger.response(str, .send)
	ls.io.send(str)
	// See line 113 for the explanation
	ls.logger.response(str, .receive)
}

// TODO: set result param type to jsonrpc.NotificationMessage<T>
// merge notify back to send method once compile-time type introspection
// supports base generic types (e.g $if T is jsonrpc.NotificationMessage)
fn (mut ls Vls) notify<T>(data T) {
	str := json.encode(data)
	ls.logger.notification(str, .send)
	ls.io.send(str)
	// See line 113 for the explanation
	ls.logger.notification(str, .receive)
}

// send_null sends a null result to the client
fn (mut ls Vls) send_null(id int) {
	str := '{"jsonrpc":"2.0","id":$id,"result":null}'
	ls.logger.response(str, .send)
	ls.io.send(str)
	ls.logger.response(str, .receive)
}

fn monitor_changes(mut ls Vls) {
	// This is for debouncing/throttling analysis
	for {
		select {
			a := <-ls.typing_ch {
				ls.is_typing = a != 0
			}
			> 50 * time.millisecond {
				if !ls.is_typing {
					continue
				}
				
				if ls.store.cur_file_path in ls.store.opened_scopes {
					unsafe {
						ls.store.opened_scopes[ls.store.cur_file_path].free()
					}
				}

				uri := lsp.document_uri_from_path(ls.store.cur_file_path)
				analyze(mut ls.store, ls.root_uri, ls.trees[uri], ls.sources[uri])
				ls.is_typing = false
				ls.show_diagnostics(uri)
				unsafe { uri.free() }
			}
		}
	}
}

// start_loop starts an endless loop which waits for stdin and prints responses to the stdout
pub fn (mut ls Vls) start_loop() {
	go monitor_changes(mut ls)

	for {
		payload := ls.io.receive() or { continue }
		ls.dispatch(payload)
	}
}

// new_pref returns a new of pref based on the given lookup paths
fn new_pref(lookup_paths ...string) &pref.Preferences {
	mut lpaths := [vlib_path, vmodules_path]
	for i := lookup_paths.len - 1; i >= 0; i-- {
		lookup_path := lookup_paths[i]
		lpaths.prepend(lookup_path)
	}
	res := &pref.Preferences{
		enable_globals: true
		output_mode: .silent
		backend: .c
		os: ._auto
		lookup_path: lpaths
		is_shared: true
	}
	return res
}

// set_features enables or disables a language feature. emits an error if not found
pub fn (mut ls Vls) set_features(features []string, enable bool) ? {
	for feature_name in features {
		feature_val := feature_from_str(feature_name) ?
		if feature_val !in ls.enabled_features && !enable {
			return error('feature "$feature_name" is already disabled')
		} else if feature_val in ls.enabled_features && enable {
			return error('feature "$feature_name" is already enabled')
		} else if feature_val !in ls.enabled_features && enable {
			ls.enabled_features << feature_val
		} else {
			mut idx := -1
			for i, f in ls.enabled_features {
				if f == feature_val {
					idx = i
					break
				}
			}
			ls.enabled_features.delete(idx)
		}
	}
}

pub enum ServerStatus {
	off
	initialized
	shutdown
}

[inline]
fn new_error(code int) jsonrpc.Response2<string> {
	return jsonrpc.Response2<string>{
		error: jsonrpc.new_response_error(code)
	}
}
