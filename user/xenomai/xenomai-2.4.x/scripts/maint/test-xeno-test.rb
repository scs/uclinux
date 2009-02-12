#!/usr/bin/env ruby

# Funning xeno-test once with each option takes a long time (around 15 minutes)
# For each test a full log is stored in the logs subdirectory.
# Therefore the results of the tests (the ruby variable) is stored using Pstore in
# the file logs/xeno-test.store.
# If this file exists and is newer than xeno-test and the first parameter is != clean
# The tst variable is fetched from the file.
# This is convenient if you want to add new checks.
#
# Todo: - Why do the mailing tests not work  ?
#       - How does xeno-test react to Ctrl-C ?
#       - Thorougher analyses of the log files
#
require 'timeout'
require 'ostruct'
require 'ftools'
require 'pstore'
require 'tempfile'

XenoInstall = "/usr/xenomai/bin"
XenoHead    = File.expand_path(File.dirname(File.dirname(__FILE__)))
XenoTestOrg = XenoHead+'/xeno-test.in'
XenoTestRun = XenoInstall+'/xeno-test'
LogDir      = XenoHead+'/logs'
MainLog     = LogDir+'/runtest.log'
StorageName = LogDir+'/xeno-test.store'
withFinished = `grep finished /usr/xenomai/bin/xeno*`
withFinished.size > 0 ? FinishedMsg = "xeno-test: finished" : FinishedMsg = nil

$clean  = ARGV[0] == 'clean' && ! (
	  File.exists?(XenoTestRun) &&
          File.exists?(StorageName) &&
          File.stat(XenoTestRun).mtime >  File.stat(StorageName).mtime
          )
if $clean && File.exists?(StorageName) then
  puts "Do you really want to run all tesst? <Ctrl-C> to abort"
  STDIN.getc
end

class XenoTest
  attr_reader :mainLog
  attr_reader :blockDevice
  attr_writer :maxTimeout
  attr_writer :chkProc

  def initialize(options)
    @from    = XenoHead
    @inst    = XenoInstall
    @busybox = false
    File.makedirs(LogDir) if defined?(LogDir) && ! File.directory?(LogDir)
    @@mainLog = open(MainLog,"w");
    @@mainLog.puts("#{Time.now}: started run")
    @@mainLog.sync = true
    options.each { |name,val|
      if val.class == String then
        cmd =  "@#{name}='#{val}'"
      else
	cmd =  "@#{name}=#{val}"
      end
      eval cmd
    }
  end

  def add(opts,  chkProc=nil)
    @nr   = -1        if !defined?(@nr)
    @tsts = Array.new if !defined?(@tsts)
    @nr  += 1
    elem = OpenStruct.new({'nr' => @nr, 'opts'=>opts})
    elem.chkProc = chkProc if chkProc
    @tsts << elem
    return elem
  end

  def runTests
    @tsts.each { |x| runOneTest(x) ; }
  end

  def XenoTest::writeLogEntry(tst, logMsg)
    msg = "#{Time.now}: #{sprintf("%2d", tst.nr)} "+ logMsg
    if ! File.exists?(MainLog) then
      puts msg
    end
    outs = [ STDOUT]
    outs << @@mainLog if defined?(@@mainLog) && @@mainLog
    outs.each {|dev| dev.puts msg }
  end

  def runOneTest(x)
    puts "runOneTest #{x.inspect}"  if $VERBOSE
    opts = x.opts
    startTime = Time.now
    tstRes = nil
    x.tst  = `which xeno-test`.chomp
    x.log  = "#{LogDir}/test_xeno_test.log.#{x.nr}"
    x.cmd  = "#{x.tst} -T 1 #{x.opts} | tee #{x.log}"   # -T 1 to make the test time shorter

    # Start thread to enfore maxTimeout
    if @maxTimeout then
      @rThread = Thread.new{
	    puts "@rThread: "+Process.pid.to_s if $VERBOSE
	    writeLogEntry(x, "started: #{opts} Timeout #{@maxTimeout}")
	    sleep(@maxTimeout);
	    writeLogEntry(x, "rThread will kill #{$childPid.inspect}")
	    system("kill -9 #{$childPid}") if $childPid
	    raise Timeout::Error 
      }
    end
    # Now we are doing calling our script
    $childPid = nil
    Dir.chdir(@inst)
    res = IO.popen(x.cmd) { |f|
      puts "cmd: "+Process.pid.to_s if $VERBOSE
      $childPid = Process.pid
      f.each{|a| puts a}
    } 
    tstRes = $?
  rescue Timeout::Error => details
    puts detail.backtrace.join("\n")
    writeLogEntry(x, "FAILED: #{opts} Timeout error #{$childPid}")
    system("kill -9 #{$childPid}")
  rescue => details
    writeLogEntry(x, "FAILED: #{opts} runtime error #{@rThread.inspect} pid #{$childPid.inspect}")
    puts details.backtrace.join("\n")
    system("kill -9 #{$childPid}")
    @rThread.kill if defined?(@rThread)
  ensure
    # save results,
    # clean up dd process if there are any, if xeno-test did not clean it up as it should have
    endTime = Time.now
    duration = (endTime-startTime).round
    if duration <= 5 then
      str    =  "FAILED"
      tstRes =  'too fast'
    else
      str = tstRes ? 'PASSED' : 'FAILED'
    end
    x.tstRes   = tstRes
    x.duration = duration
    XenoTest::writeLogEntry(x, "#{str}: #{sprintf("%3d", duration)} seconds. opts <#{x.opts}> returned #{tstRes}")

    IO.popen("ps -ef | grep -w dd") { |f|
      line= f.gets
      if ! line.index('grep') then
	msg = "#{Time.now}: #{sprintf("%2d", x.nr)} FAILED: dd not killed \n    >>> #{line}"
	[ STDOUT, @@mainLog].each {|dev| dev.puts msg if dev}
	system "killall dd"
      end
    }
    @rThread.kill if @rThread
    @rThread = nil
  end

  def runChecks
    puts "running all Checks"
    @tsts.each { |aTst|
      checkFinished(aTst)
      chks = aTst.chkProc
      next if ! chks
      z = eval "#{chks[0]}"+"(aTst, chks[1])" if chks[1]
    }
    puts "completed all Checks"
  end

  def checkFinished(tst)
    return if ! FinishedMsg
    logInhalt = IO.readlines(tst.log)
    finished  = false
    logInhalt.each{|line|
      finished =  true if line.index(FinishedMsg)
    }
    if !finished then
      puts "CHK #{tst.nr} FAILED opts #{tst.opts} could not find #{FinishedMsg}"
      puts "  searched in #{tst.log}" 
    end
  end

  def getTstByOpt(opts)
    @tsts.each{ |aTst|
      return aTst if aTst.opts == opts
    }
    return nil
  end
end

# Here follow the various routines, that check the effect of each options
def expectInLogFile(x, string)
  puts "x #{x.inspect}\nlooking for #{string}" if $VERBOSE
  logInhalt = IO.readlines(x.log)
  found = false
  logInhalt.each{|line|
    found = true if line.index(string)
  }
  puts "CHK #{x.nr} FAILED, could not find #{string} in #{x.log}" if !found
end

# Get a name for a temporary file as a target to upload via curl (option -U)
tf = Tempfile.new("xeno-test")
TstUrlTarget = tf.path
tf.close
File.delete if File.exists?(TstUrlTarget)

tst   = nil
store = nil
File.delete(StorageName) if $clean &&  File.exists?(StorageName)
if File.exists?(StorageName) then
  # Read in our saved test state (if we have a valid combination)
  store = PStore.new(StorageName)
  puts "reading tst from #{StorageName}"
  store.transaction do
    tst = store['tst']
  end
else
  # we prepare to run our tests

  # Get the first block-Device
  blockDevices = `mount | cut -d\\  -f1 | egrep -ve 'sysfs|proc|depts'`
  blockDevices = blockDevices[0..blockDevices.index("\n")].chomp
  bDev = blockDevices

  tst = XenoTest.new({'blockDevice' => bDev})
  tst.maxTimeout = 120

  # Define test run for each option and/or combination thereof
  
  # Test for a bad option. This happens to be fast, too
  tst_0  = tst.add("-O",                [ 'expectInLogFile', "xeno-test [options]"])
  tst_1  = tst.add("",                  [ 'expectInLogFile', FinishedMsg])
  tst_2  = tst.add("-T 5")
  if true then # To speed up our test,s we may turn off defining more testruns
      tst_3  = tst.add("-p 200",        ['expectInLogFile',"Sampling period: 200 us"])
      tst_4  = tst.add("-w 2",          ['expectInLogFile',FinishedMsg])
      tst_5  = tst.add("-d #{bDev}",
	  ['expectInLogFile',"creating workload using dd if=#{bDev}"])

      tst_6  = tst.add("-w /bin/dd #{bDev}",
					['expectInLogFile',FinishedMsg])
      tst_7  = tst.add("-P 'echo marker'", 
					['expectInLogFile',FinishedMsg])
      tst_8  = tst.add("-L",            ['expectInLogFile',FinishedMsg])
      tst_9  = tst.add("-N marker",     ['expectInLogFile',FinishedMsg])
      tst_10 = tst.add("-v",            ['expectInLogFile',FinishedMsg])
      tst_11 = tst.add("-U #{TstUrlTarget}",
                                        ['expectInLogFile',FinishedMsg])
      tst_12 = tst.add("-D '%Ymarker%Mmarker%D'", 
                                        ['expectInLogFile',FinishedMsg])
#      tst_13 = tst.add("-M #{ENV['USER']}@localhost", 
#					['expectInLogFile',FinishedMsg])
#      tst_14 = tst.add("-m",            ['expectInLogFile',FinishedMsg])
  end

  # Remove files, we might have left behind in a previous test
  ( Dir.glob("/tmp/test-#{`uname -r`.chomp}*") + 
    Dir.glob("#{XenoInstall}/marker*")).each { |file|
    puts "Removing #{file}"
    File.delete file
  }
  tst.runTests

  # Now we are ready to store our testresult (our ruby variable) to file
  puts "Writing tst to #{StorageName}"
  store = PStore.new(StorageName)
  store.transaction do
    store['tst'] = tst
  end
end

# If we did run the curl/-N, -L test, did it generate the expected file?
{
 "-U #{TstUrlTarget}" => TstUrlTarget,
 "-L" => "/tmp/test-#{`uname -r`.chomp}*",
 "-N marker" =>  "#{XenoInstall}/marker*",
}.each { |opt, path|
  myTst  = tst.getTstByOpt(opt)
  if myTst && Dir.glob(path).size == 0  then
    XenoTest::writeLogEntry(myTst, "FAILED: #{opt}: no file #{path} found")
  else 
    XenoTest::writeLogEntry(myTst, "PASSED: #{opt}: #{Dir.glob(path).inspect}")
  end if myTst
}

# This string is probably wrong, but I think xeno-test doesn't accept this
# string as it should neither
myTst  = tst.getTstByOpt("-D '%Ymarker%Mmarker%D'")
tstString = "-D #{Time.now.strftime('%Ymarker%Mmarker%D')}"
tstString = "marker"
expectInLogFile(myTst, tstString) if myTst

# Test whether we really take more time with -T 5 than with the default -T 1
long  = tst.getTstByOpt("-T 5")
short = tst.getTstByOpt("")
if long and short then
  if long.duration < short.duration + 5
  then
    XenoTest::writeLogEntry(long, 
      "FAILED: with '#{short.opts}' #{sprintf("%3d", short.duration)} "+
      "+ 5 not smaller <  #{sprintf("%3d", long.duration)} seconds with '#{long.opts}'.")
  end
end

tst.runChecks
