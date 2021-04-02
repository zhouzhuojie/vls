module main

import os
import lsp
import vls
import vls.testing
import time

fn main() {
	mut io := &testing.Testio{}
	mut ls := vls.new(io)

	ls.dispatch(io.request_with_params('initialize', lsp.InitializeParams{
		root_uri: lsp.document_uri_from_path(testing.test_files_dir)
	} ))

	// for _ in 0 .. 5 {
		// for test_name in ['completion', 'hover', 'workspace_symbols'] {
			test_files := testing.load_test_file_paths('hover') or { []string{} }
			mut opened_docs := []lsp.TextDocumentIdentifier{len: test_files.len}
			mut sources := []string{len: test_files.len}

			// open documents
			for test_file_path in test_files {
				content := os.read_file(test_file_path) or { continue }
				_, doc_id := io.open_document(test_file_path, content)
				sources << content
				opened_docs << doc_id
			}

			// close document
			for idx, doc_id in opened_docs {
				// edit document
				for i in 0 .. 8 {
					ls.dispatch(io.request_with_params('textDocument/didChange', lsp.DidChangeTextDocumentParams{
						text_document: lsp.VersionedTextDocumentIdentifier{
							uri: doc_id.uri
							version: i
						}
						content_changes: [lsp.TextDocumentContentChangeEvent{
							text: sources[idx]
						}]
					}))
				}

				time.sleep(2 * time.second)
				ls.dispatch(io.close_document(doc_id))
			}
		// }
	// }
}