#!/usr/bin/env ruby
##
# Malware Analysis Zoo
# https://github.com/ohdae/maz
##
# MAZ is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MAZ is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MAZ.  If not, see <http://www.gnu.org/licenses/>.
##

$LOAD_PATH.unshift File.expand_path(File.dirname(__FILE__) + '/maz')

require 'core'
require 'external'
require 'database'
require 'analyze'
require 'cli'

VERSION = "0.5 beta"
APPNAME = "Malware Analysis Zoo"
SHORT   = "MAZ"

