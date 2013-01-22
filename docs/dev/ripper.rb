#!/usr/bin/env ruby
# include the magic ripper
require "ripper.rb"
#string="uggc"
for a in [ 0x1AE88, 0x1AEF0, 0x1AF54, 0x1AF88, 0x1AFEC, 0x1B020, 0x1B084, 0x1B0B8, 0x1B0EC, 0x1B120, 0x1B184 ]
  srcFile = File.open(ARGV[0], 'r')
  srcFile.seek(a, IO::SEEK_SET)
  string = srcFile.sysread(0x20)
  specs = [Spec.new(ARGV[0], 0x403034,"unsigned int decode();", [], [], [], [], string)]
  worker = Ripper.new(specs)
  worker.runner.decode()
  puts string
end



disasm = AutoExe.decode_file(ARGV[0]).init_disassembler
# Rip function at 0x401B96 with signature int decrypt(char* in, char* in);
specs = [Spec.new(0x401B96, "int decrypt(char* in, char* out);")]
worker = Ripper.new(disasm, specs)
# For all the encrypted strings offset
for a in [0x384C, 0x3870, 0x388C, 0x38A0, 0x38C0, 0x38D0, 0x3914, 0x3930, 0x39A0, 0x3A10, 0x3A80, 0x3AF0, 0x3B60, 0x3BD0, 0x3C20, 0x3C70, 0x3C88, 0x3DA0, 0x3DD0, 0x3E00, 0x3E60, 0x3E88, 0x3EB0, 0x3EE8, 0x3F10, 0x3F64, 0x3F8C, 0x3FC4, 0x3FD8, 0x4058, 0x4098, 0x40B0, 0x4108, 0x4130, 0x4158, 0x4170, 0x41EC, 0x4200, 0x4230, 0x4270, 0x42B8, 0x42FC, 0x4310, 0x4350, 0x4398, 0x43F4, 0x44FC, 0x4508, 0x4524]
  # Read the encrypted string
  srcFile = File.open(ARGV[0], 'r')
  srcFile.seek(a, IO::SEEK_SET)
  # never longer than 0x80
  src = srcFile.sysread(0x80)
  # Allocate output
  dst = "\x00" * (src.length)
  # Decryt and output
  worker.runner.decrypt(src, dst)
  puts "#{a.to_s(16)}: #{dst}"
end


# include the magic ripper
require "ripper.rb"
# get a disassembler on first arq
disasm = AutoExe.decode_file(ARGV[0]).init_disassembler
# Rip function at 0x40350E with signature int decrypt(char* text, int length, int* key);
specs = [Spec.new(0x40350E, "int decrypt(char* text, int length, int* key);")]
# Actually rip it
worker = Ripper.new(disasm, specs)
# Setup the arguments
length = 0x310C
offset = 0x5098
srcFile = File.open(ARGV[0], 'r')
srcFile.seek(offset, IO::SEEK_SET)
src = srcFile.sysread(length)
a = "\x00" * 4
# Launch the ripped function
worker.runner.decrypt(src, length, a)
# Output text in clear
File.open(ARGV[0] + ".0x#{offset.to_s(16)}.decrypted", 'w+'){|fd| fd << src}
