#!/usr/bin/env ruby
$:.unshift(File.dirname(__FILE__))

require 'maz/core'
require 'maz/database'
require 'maz/analyze'
require 'maz/console'
require 'maz/logging'
require 'maz/cli'

module Maz
  VERSION = "1.0 gamma"
  APPNAME = "Malware Analysis Zoo"
  SHORT   = "MAZ"
end
