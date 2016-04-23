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
      spec.linker.flags << "#{dir}\\libsodium\\bin\\Win32\\Release\\v140\\static\\libsodium.lib"
    end
  else
    if spec.cc.search_header_path 'sodium.h'
      spec.linker.libraries << 'sodium'
    else
      warn "#{spec.name}: cannot find libsodium, building it"
      sh "cd #{spec.dir} && git submodule init && git submodule update && cd libsodium && ./autogen.sh && ./configure --enable-minimal --enable-opt --prefix=#{spec.dir} --disable-shared && make -j4 && make -j4 check && make install"
      spec.linker.flags << "#{spec.dir}/lib/libsodium.a"
    end
  end
  spec.add_dependency 'mruby-errno'
end
