MRuby::Gem::Specification.new('mruby-libsodium') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby bindings for libsodium'
  if spec.build.toolchains.include? 'visualcpp'
    if spec.cc.search_header_path 'sodium.h'
      spec.linker.libraries << 'libsodium'
    else
      warn "#{spec.name}: cannot find libsodium, building it"
      dir = spec.dir.gsub('/', '\\')
      spec.cc.defines << 'SODIUM_STATIC'
      sh "cd #{dir} && git submodule init && git submodule update && cd libsodium\\builds\\msvc\\build && buildbase.bat ..\\vs2015\\libsodium.sln 14"
      spec.linker.flags << "#{dir}\\libsodium\\bin\\#{ENV['Platform']}\\Release\\v140\\static\\libsodium.lib"
      spec.cc.include_paths << "#{dir}\\libsodium\\src\\libsodium\\include"
    end
  else
    if spec.cc.search_header_path 'sodium.h'
      spec.linker.libraries << 'sodium'
    else
      warn "#{spec.name}: cannot find libsodium, building it"
      ENV['CFLAGS'] = spec.cc.flags.join(' ')
      ENV['LDFLAGS'] = spec.linker.flags.join(' ')
      sh "cd #{spec.dir} && git submodule init && git submodule update && cd libsodium && ./configure --enable-minimal --prefix=#{spec.build_dir} --disable-shared && make -j4 && make -j4 check && make install"
      spec.linker.flags << "#{spec.build_dir}/lib/libsodium.a"
      spec.cc.include_paths << "#{spec.build_dir}/include"
    end
  end
  spec.add_dependency 'mruby-errno'
end
