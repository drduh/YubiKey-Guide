#!/usr/bin/env bash

# USAGE: passphrase.txt.sh [ PIN_LENGTH [ PASSPHRASE_LENGTH ]]
# PIN_LENGTH and PASSPHRASE_LENGTH can be omitted. A txt file will be written to stdout

set -e
set -u
set -o pipefail

# Script arguments, or use defaults
PIN_LENGTH="${1:-8}"
PASSPHRASE_LENGTH="${2:-30}"

DATE_HEADER=$(cat <<EOF
    DATE (YYYY-MM-DD)      
                           
       2025-__-__          
                           
         KEY ID            
   0x________________      
                           
      SERIAL NUMBER        
        ________           
EOF
)


DATE_HEADER="$DATE_HEADER$(for ((i=8; i<=PIN_LENGTH; i++)); do printf '\n                           '; done)"

KEYS=$(cat <<EOF
     ADMIN PIN                  USER PIN     

$(for ((i=1; i<=PIN_LENGTH; i++)); do
	echo "0 1 2 3 4 5 6 7 8 9       0 1 2 3 4 5 6 7 8 9"
done)
EOF
)

echo "# https://github.com/drduh/YubiKey-Guide/blob/master/templates/passphrase.txt"
echo ""

paste -d " " <(echo "$DATE_HEADER") <(echo "$KEYS")

cat <<EOF

                        FOR EACH CHAR IN PASSPHRASE,
                MARK CORRESPONDING COLUMN ON SEQUENTIAL ROW,
                      THEN FOLD INWARD AND TAMPER SEAL

EOF

for ((i=1; i<=PASSPHRASE_LENGTH; i++)); do
	echo "- A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 0 1 2 3 4 5 6 7 8 9"
done
echo ""
