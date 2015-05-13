BASH_CMD = {
	'GET_MIME_TYPE' : "file %(file_path)s"
}

PROOF_OF_EXISTENCE_IO = {
	'STATUS' : "%(POE_URL)s/status",
	'REQUEST' : "%(POE_URL)s/request"
}

MD_FORMATTING_SENTINELS = {
	'code_block' : {
		'standard' : ["```", "```"],
		'jekyll' : ["{%% highlight text %%}", "{%% endhighlight %%}"]
	},
	'json' : {
		'standard' : ["```", "```"],
		'jekyll' : ["{%% highlight json %%}", "{%% endhighlight %%}"]
	},
	'frontmatter' : {
		'jekyll' : ["---", "layout: notary", \
			"title: %(doc_hash)s", "date: %(date_admitted_str_md)s", "---\n"]
	}
}