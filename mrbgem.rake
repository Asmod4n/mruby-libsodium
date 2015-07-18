MRuby::Gem::Specification.new('mruby-libsodium') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby bindings to libsodium'
  spec.linker.libraries << 'sodium'
  spec.add_dependency 'mruby-errno'
end
