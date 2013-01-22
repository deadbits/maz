#!/usr/bin/env ruby
##
##
require 'readline'

class Maz
  def status(data); puts "[maz]   #{data}"; end
  def error(data); puts "[error] #{data}"; end
  def info(data); puts "[info]  #{data}"; end

	def help_menu
		$commands = {
			'help' => 'displays this command menu',
			'load' => 'load a new sample into maz',
			'submit' => 'analyze loaded sample and save to database',
			'analyze' => 'analyze loaded sample and return report without saving to database',
			'search' => 'search database for sample by hash or name',
			'anubis' => 'submit sample to anubis and retrieve report',
			'clear' => 'clears the screen using system call',
			'report' => 'generate and view report for sample',
			'info' => 'view raw data for sample',
			'quit' => 'exit the maz console',
			'exit' => 'exit the maz console',
			'about' => 'display about information' }.sort
		$commands.each_pair do |k, v|
			puts "#{k}\t#{v}"
		end
	end

  def about_menu
    puts %{"MAZ or Malware Analysis Zoo, is a Ruby platform that performs static malware analysis, sample storage and querying and
      external scanner submissions. MAZ was created and maintained by Adam M. Swanda. The full source-code and Wiki documentation
      can be viewed at https://github.com/ohdae/MAZ. There is also a collection of stand-alone scripts that provie easy access to
      some of the more basic features, called MAZ-Mini. Thanks for using MAZ and happy hunting!"}
  end

  def start
		comp = proc { |s| $commands.grep ( /^#{Regexp.escape(s)}/ ) }
		Readline.completion_append_character = " "
		Readline.completion_proc = comp

		while line = Readline.readline('maz >> ', true)
			case line
				when line =~ /about/
					about_menu
				when line =~ /help/
					help_menu
				when line =~ /exit/
					status("shutting down maz console...")
					exit(0)
				when line =~ /quit/
					status("shutting down maz console...")
					exit(0)
				when line =~ /submit/
					info("feature not yet available.")
				else
					info("feature not yet available.")
			end
		end
	end
end


Maz.start

