#!/usr/bin/awk -f

# Usage: foo <template> <file>
# Searches through file for instances of 'kern_return_t $FOO'
# where $FOO is an line in the template file
# and prepends the first line in the template file.

# Example template format:
#       %{
#       __WATCHOS_PROHIBITED
#       %}
#       act_get_state
#       thread_get_state
# 

# BEGIN { print ARGV[1]; print ARGV[2] }

# In the first file, build array of lines
NR==FNR && /^ *$/ {
	next
}
NR==FNR && /^#/ {
	next
}
NR==FNR && /%{/ {
	parse_prefix = 1
	prefix = ""
	next
}
NR==FNR && /^%}/ {
	parse_prefix = 0
	next
}
NR==FNR {
	if (parse_prefix && length(prefix)) {
		prefix = sprintf("%s\n%s", prefix, $0)
	} else if (parse_prefix) {
		prefix = $0
	} else if (length(templates[$0])) {
		templates[$0] = sprintf("%s\n%s", templates[$0], prefix)
	} else {
		templates[$0] = prefix
	}
	next
}

# In the second file, match kern_return_t <template>
# at the beginning of the line
# print the prefix line if found

/^kern_return_t/ {
#	print "match"
	if ($2 in templates) {
		print templates[$2]
	}
}

# Pass through everything in the second file
{ print }
