#!/usr/bin/env python3
import sys
import os

template = '''#!/bin/zsh
tests=(
TEST_TARGETS
)

exit_success=0
exit_skip=69

s_dir=${0:A:h}
err_count=0
for file in ${tests[@]}; do
  file_path=$s_dir/$file
  echo "Running $file_path ..."
  if [[ -f $file_path ]]; then
    $file_path > /dev/null 2>/dev/null
    ret=$?
    if [[ $ret -eq $exit_success || $ret -eq $exit_skip ]]; then
      print -P "%F{green}*** PASS%f"
    else
      print -P "%F{red}*** FAILED: $file_path%f"
      ((err_count++))
    fi
  else
    print -P "%F{yellow}*** Missing%f"
    ((err_count++))
  fi
done
if [[ $err_count -gt 0 ]]; then
  print -P "%F{red}Failed: $err_count%f"
  exit 1
fi  
exit 0
'''

def main():
    targets_s = sys.argv[1]
    output = sys.argv[2]
    output_list = sys.argv[3]

    targets = targets_s.strip().split(' ')
    target_lines = '\n'.join([('"' + t + '"') for t in targets])
    s = template.replace('TEST_TARGETS', target_lines)
    open(output, 'w').write(s)
    print(f"wrote {output}")

    open(output_list, 'w').write('\n'.join(targets) + '\n')
    print(f"wrote {output_list}")

if __name__ == "__main__":
  sys.exit(main())
