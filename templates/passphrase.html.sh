#!/usr/bin/env bash

# USAGE: passphrase.html.sh [ PIN_LENGTH [ PASSPHRASE_LENGTH ]]
# PIN_LENGTH and PASSPHRASE_LENGTH can be omitted. A HTML file will be written to stdout

set -e
set -u
set -o pipefail


# Script arguments, or use defaults
PIN_LENGTH="${1:-8}"
PASSPHRASE_LENGTH="${2:-30}"

cat <<EOF
<!DOCTYPE html>
<!-- https://github.com/drduh/YubiKey-Guide/blob/master/templates/passphrase.html
     https://raw.githubusercontent.com/drduh/YubiKey-Guide/master/templates/passphrase.html
     Save the raw file ^ then open in a browser to render and print -->
<html lang="en-US">
  <head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="github.com/drduh/YubiKey-Guide">
  <title>credentials</title>
  <style>
  :root {
    --color-dark: #000000;
    --color-gray: #dedede;
  }
  body {
    color:        var(--color-dark);
    font-family:  monospace;
    font-size:    0.8rem;
    font-variant: small-caps;
    text-align:   center;
  }
  td {
    border:       0.05rem solid var(--color-dark);
    height:       1rem;
    min-width:    1rem;
  }
  td.alt, tr.alt {
    background:   var(--color-gray);
  }
  </style>
</head>

<body>
  <table>
  <colgroup span="38"></colgroup>
  <tr>
    <td></td>
    <td class="alt" colspan="10">date (yyyy-mm-dd)</td>
    <td></td>
    <td></td>
    <td></td>
    <td class="alt" colspan="10">admin pin</td>
    <td></td>
    <td></td>
    <td></td>
    <td class="alt" colspan="10">user pin</td>
    <td></td>
  </tr>
EOF

DATE_HEADER=$(cat <<EOF
<tr><td></td><td>2</td><td>0</td><td>2</td><td>5</td><td>-</td><td>_</td><td>_</td><td>-</td><td>_</td><td>_</td><td></td><td></td><td></td>
<tr>$(for((i=0;i<14;i++)); do printf "<td></td>"; done)
<tr><td></td><td class="alt" colspan="10">key id</td><td></td><td></td><td></td>
<tr><td></td><td class="alt" colspan="2" rowspan="2">0x</td> $(for((i=0;i<8;i++)); do printf "<td>_</td>"; done)<td></td><td></td><td></td>
<tr><td></td>$(for((i=0;i<8;i++)); do printf "<td>_</td>"; done)<td></td><td></td><td></td>
<tr>$(for((i=0;i<14;i++)); do printf "<td></td>"; done)
<tr><td></td><td class="alt" colspan="10">serial number</td><td></td><td></td><td></td>
<tr><td></td>$(for((i=0;i<10;i++)); do printf "<td>_</td>"; done)<td></td><td></td><td></td>
EOF
)

KEYS=$(cat <<EOF
$(for ((i=1; i<=PIN_LENGTH; i++)); do
	for j in {1..10}; do
		printf "<td>$j</td>"; 
	done && 
	printf "<td></td><td></td><td></td>"
	for j in {1..10}; do
		printf "<td>$j</td>"; 
	done && 
	printf "<td></td></tr>\n"
done)
EOF
)

#Make KEYS have as many lines as DATE_HEADER, and vice versa. Needed to close/open html tags properly
# Note that the row is simply closed without filling it up...
KEYS="$KEYS $(for ((i=PIN_LENGTH; i<8; i++)); do printf '\n' && for _ in {0..23}; do printf '<td></td>'; done && printf '</tr>'; done)"
DATE_HEADER="$DATE_HEADER $(for ((i=8; i<PIN_LENGTH; i++)); do printf '\n<tr>' && for _ in {0..13}; do printf '<td></td>'; done ; done)"

paste -d " " <(echo "$DATE_HEADER") <(echo "$KEYS")

cat <<EOF
<tr class="alt">
    <td colspan="38">for each char in passphrase, mark corresponding column on sequential row, then fold inward and tamper seal</td>
  </tr>
EOF

for ((i=1; i<=PASSPHRASE_LENGTH; i++)); do

if [ $((i%2)) -eq 0 ]; then
	printf '<tr class="alt">';
else
	printf '<tr>';
fi

cat <<EOF
    <td>-</td>
    <td>A</td>
    <td>B</td>
    <td>C</td>
    <td>D</td>
    <td>E</td>
    <td>F</td>
    <td>G</td>
    <td>H</td>
    <td>I</td>
    <td>J</td>
    <td>K</td>
    <td>L</td>
    <td>M</td>
    <td>N</td>
    <td>O</td>
    <td>P</td>
    <td>Q</td>
    <td>R</td>
    <td>S</td>
    <td>T</td>
    <td>U</td>
    <td>V</td>
    <td>W</td>
    <td>X</td>
    <td>Y</td>
    <td>Z</td>
    <td>0</td>
    <td>1</td>
    <td>2</td>
    <td>3</td>
    <td>4</td>
    <td>5</td>
    <td>6</td>
    <td>7</td>
    <td>8</td>
    <td>9</td>
    <td></td>
  </tr>
EOF
done

cat <<EOF
</table>
</body>
</html>
EOF



