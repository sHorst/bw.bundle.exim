#!/usr/bin/env zsh

echo "default_configs = {"
foreach dir (files/conf.d/*); do
    echo "    '$(basename $dir)': {"
    foreach file ($dir/*); do
        prio=$(basename "$file" | cut -d '_' -f 1)
        name=$(basename "$file" | cut -d '_' -f 2-)

        echo "        '$name': {"
        echo "            'prio': $prio,"
        echo "            'content': ["
        cat "$file" | sed "s/\\\\/\\\\\\\\/g" | sed "s/'/\\\\'/g" | sed "s/^/                '/g" | sed "s/$/',/g"

        echo "            ],"
        echo "        },"
    done
    echo "    },"
done
echo "}"
