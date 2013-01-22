#!/usr/bin/env ruby
# Malware Analysis Zoo
# https://github.com/ohdae/maz
# quick and easy command line app

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '../lib'))

require 'maz'
require 'trollop'
require 'rubygems'

Maz::CLI.new

