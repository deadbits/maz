#!/usr/bin/env ruby
##
# Malware Analysis Zoo
# name: console.rb
# desc: this is the console interface
# to MAZ. you can analyze all the malwares
# from here :D
##

#require 'pry'
require 'readline'
require File.expand_path("#{File.dirname __FILE__}/lib/maz")

class Console
  Core = Maz::Core.new
  Analyze = Maz::Analyze.new
  External = Maz::External.new
  Database = Maz::Database.new

  @help = %{"

      for full support, review the files in the 'docs' directory.
      in this menu, '[sample]' refers to any of the following:
        md5 hash - sha256 hash - filename - mID

    :::General Commands:::
      help                       -   display this menu
    report [html/txt] [sample]   -   generate report on [sample]
    search [sample]              -   query database for [sample]
    recent [count]               -   show [count] most recent submissions
      exit                       -   shutdown the MAZ console
     
    :::Analysis Commands:::
      load [file/directory]      -   add [file] or [directory] to queue
   analyze [file]                -   analyze [file], report and submit to database
    cuckoo [sample]              -   spin up [sample] in Cuckoo instance
    anubis [sample]              -   submit [sample] to Anubis and get report 
    vtotal [sample]              -   submit [sample] to VirusTotal and get report
   threatx [sample]              -   query ThreatExpert for [sample]\n\n"}

  @commands = {
    'help' => @help,
    'report' => nil,
    'search' => nil,
    'recent' => nil,
    'exit' => nil,
    'load' => nil,
    'analyze' => nil
  }

  def cmd_dispatch(command, *args)
    @commands.each_pair do |cmd, func|
      if cmd =~ /command/
        Core.status("executing ...")
        execute.func(*args)
      end
    end
  end

  def start!
    comp = proc { |s| @commands.grep ( /^#{Regexp.escape(s)}/ ) }
    Readline.completion_append_character = " "
    Readline.completion_proc = comp

    while cmd = Readline.readline("maz >> ", true)
      case cmd
        when cmd == "exit"
          Core.shutdown
        when cmd == "help\r\n"
          puts @help
        else
          if cmd.include?(" ")
            cmd, arg = cmd.split(" ")[0], cmd.split(" ")[1]
            @commands.each_key do |c|
              if c == cmd
                cmd_dispatch(cmd, arg)
              end
            end
            Core.error("command #{cmd} is not valid.")
          else
            Core.error("command #{cmd} requires an argument.")
          end
      end
    end
  end
end

Session = Console.new
Session.start!
