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

	for test_name in ['completion', 'hover', 'workspace_symbols'] {
		test_files := testing.load_test_file_paths(test_name) or { []string{} }
		mut opened_docs := []lsp.TextDocumentIdentifier{len: test_files.len}

		// open documents
		for test_file_path in test_files {
			content := os.read_file(test_file_path) or {
				io.bench.fail()
				eprintln(io.bench.step_message_fail('file $test_file_path is missing'))
				continue
			}

			_, doc_id := io.open_document(test_file_path, content)
			opened_docs << doc_id
			time.sleep(2 * time.second)
		}

		for doc_id in opened_docs {
			ls.dispatch(io.close_document(doc_id))
		}
	}
}