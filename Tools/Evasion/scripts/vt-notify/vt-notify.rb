#!/usr/bin/env ruby
# encoding: utf-8
#
# Slightly modified version of VT-Notify that
# accepts gmail credentials for alerting.
#
# All credit to mubix https://github.com/mubix/vt-notify
#


$PROGRAM_NAME = 'VirusTotalNotifier'

# Require 'rubygems' # Uncomment this for use w/ ruby 1.8.7
require 'json'
require 'net/http'
require 'digest/sha1'
require 'optparse'
require 'net/smtp'

def send_email(to,opts={})
    # http://fuelyourcoding.com/emailify-your-app-with-gmail-and-ruby/
    Gmail.new($gmailusername, $gmailpassword) do |gmail|
        gmail.deliver do
          to "#{to}"
          subject "Virus Total Detection"
          text_part do
            body "#{opts[:body]}"
          end
        end
    end
end


def getsha1(filename)
    begin
        contents = open(filename, "rb") {|io| io.read }
        sha1 = Digest::SHA1.hexdigest(contents)
        return sha1
    rescue
        return
    end
end

def ping_vt(resource)
    url = 'http://www.virustotal.com/vtapi/v2/file/report'
    uri = URI.parse(url)
    response = Net::HTTP.post_form(uri, {"apikey" => $apikey, "resource" => resource})
    return response
end

def breakuplist(hashlist)
    hashgroup = []
    (0.step(hashlist.size, 25)).each do |x|
        hashgroup << hashlist[x..(x+25)]
    end
    return hashgroup
end

def parse_results(result, hashNameList)
    if result['response_code'] == 0
        $notfound += 1
        return
    else
        $found << result['resource']
        puts "#{result['resource']}:#{hashNameList[result['resource']]} was found #{result['positives']} out of #{result['total']} on #{result['scan_date']}"
    end
end

######### MAIN #############
argcheck = 0

# Parse arguments
OptionParser.new do |o|
    o.on('-e EMAIL // email address of who to notify upon detection, will only log to file if not specified') { |emailaddr| $emailaddr = emailaddr }
    o.on('-c CREDFILE // file a username[tab] password of gmail account to send through, defaults to creds.txt') { |credfile| $credfile = credfile; argcheck = 1 }
    o.on('-s FILENAME // file name of binary to keep track of') { |binname| $binname = binname; argcheck = 1 }
    o.on('-S SHA1 // single SHA1 to keep track of') { |sha1arg| $sha1arg = sha1arg; argcheck = 1 }
    o.on('-f FILENAME // file containing sha1 hashes of files to keep track of') { |hashfilename| $hashfilename = hashfilename; argcheck = 1 }
    o.on('-d DIRECTORY // directory of binaries keep track of') { |directory| $directory = directory; argcheck = 1 }
    o.on('-a APIKEYFILENAME // file contianing API key hash on first line, defaults to apikey.txt') { |apikeyfile| $apikeyfile = apikeyfile}
    o.on('-l LOGFILENAME // file to write/read positive entries to/from, defaults to results.log') { |logfilename| $logfilename = logfilename}
    o.on('-i INTERVAL // how often VT is checked, defaults to every 30 minutes. Use 0 for a single run.') { |interval| $interval = interval.to_i }
    o.on('-h') { puts o; exit }
    o.parse!
end

if argcheck == 0
    puts 'No hash input arguments specified. Exiting'
    exit
end

# Make sure arguments have something useful
$interval ||= 1800 # 10 minutes in seconds
$found = []
$logfilename ||= 'results.log'
$apikeyfile ||= 'apikey.txt'
$credfile ||= 'creds.txt'

# See the following blog post, but since API limits are based on KEY+IP,
# the VT peeps recommend using an application specific key distributed w/ the tool:
# http://blog.virustotal.com/2012/12/public-api-request-rate-limits-and-tool.html

begin
    $apikey = File.open($apikeyfile) {|f| f.readline.strip}
rescue Errno::ENOENT
    puts 'API key file not found. Using built-in: e09d42ac15ac172f50c1e340e551557d6c46d2673fc47b53ef5977b609d5ebe5'
    $apikey = 'e09d42ac15ac172f50c1e340e551557d6c46d2673fc47b53ef5977b609d5ebe5'
end

begin
    $gmailcreds = File.open($credfile) {|f| f.readline.strip}
    $gmailusername = $gmailcreds.split[0]
    $gmailpassword = $gmailcreds.split[1]
rescue Errno::ENOENT
    puts 'Gmail credentials not found, can\'t send email...'
end

puts "Using API key: #{$apikey}"


loop {

    hashlist = []
    hashNameList = Hash.new

    if $binname
        begin
            sha = getsha1($binname)
            hashlist << sha
            hashNameList[$binname] = sha
        rescue Errno::ENOENT
            puts 'Binary not found, exiting'
            exit
        end
    end

    if $hashfilename
        begin
            File.open($hashfilename, 'r').each_line do |line|
                hash, name = line.strip.split(":")
                hashlist << hash
                hashNameList[hash] = name
            end
        rescue Errno::ENOENT
            puts 'Hash file not found, exiting'
            exit
        end
    end

    if $sha1arg
        hashlist << $sha1arg
        hashNameList[$sha1arg] = nil
    end

    if $directory
        begin
            wd = Dir.getwd
            Dir.chdir($directory)
            filelist = Dir['**/*'].reject {|fn| File.directory?(fn)}
            puts 'Generating SHA1 of all files in directory recursively, this could take a while'
            puts 'This is done each for each check just in case files change.'
            filelist.each do |file|
                sha = getsha1(file)
                hashlist << sha
                hashNameList[file] = sha
            end
            # Return to working directory
            Dir.chdir(wd)
        rescue Errno::ENOENT
            puts 'No such folder specified for -d, please insert 5¢ and try again'
            Dir.chdir(wd)
            exit
        end
    end

    if hashlist.size == 0
        puts 'Hash list is empty for one reason or another'
        puts 'I will sleep for 30 seconds and then check again'
        sleep(30)
        next
    end

    # Remove already detected
    $found.each do |removeme|
        hashlist.delete(removeme)
    end


    hashgroup = []
    $notfound = 0
    hashgroup = breakuplist(hashlist)

    # Delete any empty groups as a result of the list being divisible by 25
    hashgroup.delete([])

    # Puts hashgroup.inspect
    apiminutelimit = 1
    hashgroup.each do |group|
        response = ping_vt(group.join(','))
        if apiminutelimit == 4
            puts 'Virus Total API limits 4 requests per minute, limit reached, sleeping for 60 seconds'
            apiminutelimit = 0
            sleep(60)
        else
            apiminutelimit += 1
        end

        if response.body != nil
            results = JSON.parse(response.body)

            if results.class == Array
                results.each do |result|
                    parse_results(result, hashNameList)
                end
            elsif results.class == Hash
                parse_results(results, hashNameList)
            end
        else
            puts "No response from Virus Total, delaying for 10 seconds and trying again..."
            sleep(10)
            redo
        end
    end

    #system("clear")
    puts ""
    puts " ======================================"
    puts "          VT-Notify    RESULTS         "
    puts " ======================================"
    puts " Checked:     #{hashlist.size}"
    puts " Not found:   #{$notfound.to_s}"
    puts " Found:       #{$found.size}"
    puts ""

    if ($interval == 0)
        puts "single check complete, exiting"
        exit
    else
        puts "check complete, sleeping for #{$interval} seconds"
        sleep($interval)
    end
}
