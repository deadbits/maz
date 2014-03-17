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

require 'socket'
require 'syslog'
require 'openssl'
require 'logger'

module Maz
  class Logging < Maz::Core

    include Logger::Severity

    def initialize(options)
      @facility = Syslog::LOG_INFO
      @severity = Logger::UNKNOWN
      @syslog_host = options["host"] || "localhost"
      @syslog_port = options["port"] || "514"
      @app_name = "maz"
      @local_ip = local_ip
      #if options['ssl']
      #  @syslog_ssl = true
      #end
    end

    def local_ip
      local = Socket.ip_address_list.detect{|i| i.ipv4_private}.ip_address
      return local unless local.nil?
    end

    def format(s)
      data = "file=#{s[:file_name]} type=#{s[:file_type]} size=#{s[:file_size]}"
      data << "path=#{s[:location]} submitted=#{s[:time]}"
      data << "md5=#{s[:md5_hash]} sha1=#{s[:sha1_hash]}"
      data << "tags=[#{s[:tags]}]"
      if s[:shadow]
        data << "shadow_first=#{s[:shadow][:first]} shadow_last=#{s[:shadow][:last]}"
        data << "shadow_type=#{s[:shadow][:type]} shadow_av=#{s[:shadow][:avres]}"
      end
      return data.to_s
    end

    #def ssl_socket
    #  ssl_setup = OpenSSL::SSL::SSLContext.new
    #  ssl_setup.cert = OpenSSL::X509::Certificate.new(File.open(@syslog_cert))
    #  ssl_setup.key = OpenSSL::PKey::RSA.new(File.open(@syslog_key))
    #  ssl_setup.verify_mode = OpenSSL::SSL::VERIFY_PEER
    #  ssl_setup.ca_file = @syslog_ca
    #  ssl_sock = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_setup)
    #  ssl_sock.sync_close = true
    #  ssl_sock.connect
    #  return ssl_sock
    #end

    def send(data)
      msg = format(data)
      sock = TCPSocket.new(@syslog_host, @syslog_port)
      syslog_msg = "<#{@facility + @severity}>#{Time.now.strftime}('%b %e %H:%M:%S')} #{@local_ip} [#{@app_name}]: #{syslog_msg}\n"
      sock.write(syslog_msg)
      sock.close
    end

  end
end
