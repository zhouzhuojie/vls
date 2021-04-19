module vls

import json
import lsp
import v.parser
import v.pref
import v.ast
import v.errors
import v.checker
import os

const (
	vroot         = os.dir(@VEXE)
	vlib_path     = os.join_path(vroot, 'vlib')
	vmodules_path = os.join_path(os.home_dir(), '.vmodules')
	builtin_path  = os.join_path(vlib_path, 'builtin')
)

fn (mut ls Vls) did_open(_ int, params string) {
	did_open_params := json.decode(lsp.DidOpenTextDocumentParams, params) or { ls.panic(err.msg) }
	source := did_open_params.text_document.text
	uri := did_open_params.text_document.uri
	ls.process_file(source, uri)
}

[manualfree]
fn (mut ls Vls) did_change(_ int, params string) {
	did_change_params := json.decode(lsp.DidChangeTextDocumentParams, params) or {
		ls.panic(err.msg)
	}
	source := did_change_params.content_changes[0].text
	uri := did_change_params.text_document.uri
	unsafe { ls.sources[uri.str()].free() }
	ls.process_file(source, uri)
}

fn (mut ls Vls) did_close(_ int, params string) {
	did_close_params := json.decode(lsp.DidCloseTextDocumentParams, params) or { ls.panic(err.msg) }
	uri := did_close_params.text_document.uri
	file_dir := uri.dir()
	mut no_active_files := true
	ls.sources.delete(uri.str())
	ls.files.delete(uri.str())
	for f_uri, _ in ls.files {
		if f_uri.starts_with(file_dir) {
			no_active_files = false
			break
		}
	}
	if no_active_files {
		ls.free_table(file_dir, did_close_params.text_document.uri)
	}
	// NB: The diagnostics will be cleared if:
	// - TODO: If a workspace has opened multiple programs with main() function and one of them is closed.
	// - If a file opened is outside the root path or workspace.
	// - If there are no remaining files opened on a specific folder.
	if no_active_files || !uri.starts_with(ls.root_uri) {
		// clear diagnostics
		ls.publish_diagnostics(uri, []lsp.Diagnostic{})
	}
}

// TODO: edits must use []lsp.TextEdit instead of string
[manualfree]
fn (mut ls Vls) process_file(source string, uri lsp.DocumentUri) {
	ls.sources[uri.str()] = source.bytes()
	file_path := uri.path()
	target_dir := os.dir(file_path)
	target_dir_uri := uri.dir()
	// ls.log_message(target_dir, .info)
	scope, mut pref := new_scope_and_pref(target_dir, os.dir(target_dir), os.join_path(target_dir,
		'modules'), ls.root_uri.path())
	if uri.ends_with('_test.v') {
		pref.is_test = true
	}

	ls.free_table(target_dir_uri, file_path)
	ls.tables[target_dir_uri] = ls.new_table()

	mut parsed_files := []ast.File{}
	mut checker := checker.new_checker(ls.tables[target_dir_uri], pref)

	if target_dir_uri in ls.file_names {
		cur_mod_files := ls.file_names[target_dir_uri].filter(it != uri)
		parsed_files << cur_mod_files.map(ls.files[it])
	} else {
		cur_mod_files := os.ls(target_dir) or { [] }
		other_files := pref.should_compile_filtered_files(target_dir, cur_mod_files).filter(it != file_path)
		parsed_files << parser.parse_files(other_files, ls.tables[target_dir_uri], pref, scope)
	}
	
	parsed_files << parser.parse_text(source, file_path, ls.tables[target_dir_uri], .skip_comments, pref,
		scope)

	import_errors := ls.parse_imports(parsed_files, mut ls.tables[target_dir_uri], pref, scope)
	checker.check_files(parsed_files)
	ls.insert_files(parsed_files)
	for err in import_errors {
		err_file_uri := lsp.document_uri_from_path(err.file_path)
		ls.files[err_file_uri].errors << err
		unsafe { err_file_uri.free() }
	}

	ls.show_diagnostics(uri)
	unsafe {
		import_errors.free()
		parsed_files.free()
		source.free()
	}
}

[manualfree]
fn get_import_dir_and_files(mod string, prefs &pref.Preferences) ?(string, []string) {
	for path in prefs.lookup_path {
		mod_dir := os.join_path(path, mod.split('.').join(os.path_separator))

		// if directory does not exist, proceed to another lookup path
		if !os.exists(mod_dir) {
			continue
		}
		
		mut files := os.ls(mod_dir) or { 
			// break loop if files is empty
			break
		}

		filtered_files := prefs.should_compile_filtered_files(mod_dir, files)
		unsafe { files.free() }

		// return error if given directory is empty
		if filtered_files.len == 0 {
			unsafe { filtered_files.free() }
			return error('module `$mod` is empty')
		}
		
		return mod_dir, filtered_files
	}

	return error('cannot find module `$mod`')
}

fn (ls Vls) mod_already_imported(dir_uri lsp.DocumentUri, mod string) bool {
	done_imports := ls.imports[dir_uri] or { return false }
	for imp in done_imports {
		if imp[0] == mod {
			return true
		}
	}

	return false
}

// NOTE: once builder.find_module_path is extracted, simplify parse_imports
[manualfree]
fn (mut ls Vls) parse_imports(parsed_files []ast.File, mut table ast.Table, prefs &pref.Preferences, scope &ast.Scope) []errors.Error {
	// mut newly_parsed_files := []ast.File{}
	mut errs := []errors.Error{}
	mut done_imports := parsed_files.map(it.mod.name)
	mut done_imports2 := []string{}
	// NB: b.parsed_files is appended in the loop,
	// so we can not use the shorter `for in` form.
	for file in parsed_files {
		file_uri := lsp.document_uri_from_path(file.path)
		
		for _, imp in file.imports {
			// skip if mod is already imported
			if ls.mod_already_imported(file_uri.dir(), imp.mod) {
				continue
			}

			imp_mod_dir, files := get_import_dir_and_files(imp.mod, prefs) or {
				errs << errors.Error{
					message: err.msg
					file_path: file.path
					pos: imp.pos
					reporter: .checker
				}
				continue
			}

			imp_mod_dir_uri := lsp.document_uri_from_path(imp_mod_dir)
			if imp_mod_dir_uri !in ls.tables {
				ls.log_message('Module `${imp.mod}` is not yet present. Importing...', .info)
				ls.tables[imp_mod_dir_uri] = ls.new_table()

				mut tmp_new_parsed_files := parser.parse_files(files, ls.tables[imp_mod_dir_uri], prefs, scope)
				mut clean_new_file_names := []string{}
				for i := 0; i < tmp_new_parsed_files.len; {
					if tmp_new_parsed_files[i].mod.name !in done_imports {
						if tmp_new_parsed_files[i].mod.name !in clean_new_file_names {
							clean_new_file_names << tmp_new_parsed_files[i].mod.name
						}

						i++
						continue
					}

					unsafe { tmp_new_parsed_files[i].free() }
					tmp_new_parsed_files.delete(i)
				}

				// ignore errors
				ls.parse_imports(tmp_new_parsed_files, mut ls.tables[imp_mod_dir_uri], prefs, scope)
				
				// mark as done
				ls.imports[file_uri.dir()] << [imp.mod, imp_mod_dir_uri]

				if imp_mod_dir_uri !in ls.symbol_locations {
					for ifile in tmp_new_parsed_files {
						ls.extract_symbol_locations(lsp.document_uri_from_path(ifile.path), ifile.mod.name, ifile.stmts)
					}
				}

				unsafe {
					files.free()
					clean_new_file_names.free()
					for j := 0; j < tmp_new_parsed_files.len; j++ {
						tmp_new_parsed_files[j].free()
					}
					tmp_new_parsed_files.free()
				}
			} 
			
			if imp.mod !in done_imports2 {
				ls.log_message('Module `${imp.mod}` already imported. copying it to ${file_uri.dir()}\'s table...', .info)

				// copy existing table data to the parent table
				// primitive implementation
				for _, type_sym_idx in ls.tables[imp_mod_dir_uri].type_idxs {
					table.register_type_symbol(ls.tables[imp_mod_dir_uri].type_symbols[type_sym_idx])
				}

				for _, fnd in ls.tables[imp_mod_dir_uri].fns {
					table.register_fn(fnd)
				}

				// TODO:
				// for fn_g_types 

				// Register
				done_imports2 << imp.mod
			}
		}

		unsafe { file_uri.free() }
	}

	// remove imports
	dir_uri := lsp.document_uri_from_path(parsed_files[0].path).dir()
	for imp in ls.imports[dir_uri] {
		imp_uri := imp[1]
		mut has_files := false
		for file_uri, _ in ls.files {
			if lsp.DocumentUri(file_uri).dir() == imp_uri {
				ls.log_message('$imp_uri has files. Skip deletion.', .info)
				has_files = true
				break
			}
		}

		if !has_files {
			unsafe {
				ls.tables[imp_uri].free()
				ls.tables.delete(imp_uri)

				if imp_uri in ls.imports {
					for dep in ls.imports[imp_uri] {
						dep.free()
					}

					ls.imports[imp_uri].free()
					ls.imports.delete(imp_uri)
				}
			}		
		}

	}
	ls.log_message(ls.imports.str(), .info)

	unsafe { 
		done_imports.free()
		done_imports2.free()
		// for file in newly_parsed_files {
		// 	file.free()
		// }
		// newly_parsed_files.free()
	}
	return errs
}
