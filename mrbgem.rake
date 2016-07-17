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
      unless File.exists?("#{dir}\\libsodium\\bin\\#{ENV['Platform']||'Win32'}\\Release\\v140\\static\\libsodium.lib")
        sh "cd #{dir} && git submodule init && git submodule update && cd libsodium\\builds\\msvc\\build && buildbase.bat ..\\vs2015\\libsodium.sln 14"
      end
      spec.linker.flags << "#{dir}\\libsodium\\bin\\#{ENV['Platform']||'Win32'}\\Release\\v140\\static\\libsodium.lib"
      spec.cc.include_paths << "#{dir}\\libsodium\\src\\libsodium\\include"
    end
  else
    if spec.cc.search_header_path 'sodium.h'
      spec.linker.libraries << 'sodium'
    else
      warn "#{spec.name}: cannot find libsodium, building it"
      unless File.exists?("#{spec.build_dir}/lib/libsodium.a")
        cc = ENV['CC']
        ld = ENV['LD']
        ar = ENV['AR']
        cflags = ENV['CFLAGS']
        ldflags = ENV['LDFLAGS']
        ENV['CC'] = build.cc.command
        ENV['LD'] = build.linker.command
        ENV['AR'] = build.archiver.command
        ENV['CFLAGS'] = spec.cc.flags.join(' ')
        ENV['LDFLAGS'] = spec.linker.flags.join(' ')
        if build.is_a?(MRuby::CrossBuild) && build.host_target && build.build_target
          sh "cd #{spec.dir} && git submodule init && git submodule update && cd libsodium && ./configure --enable-minimal --prefix=#{spec.build_dir} --disable-shared --host=#{build.host_target} --build=#{build.build_target} && make clean && make -j4 && make install"
        else
          sh "cd #{spec.dir} && git submodule init && git submodule update && cd libsodium && ./configure --enable-minimal --prefix=#{spec.build_dir} --disable-shared && make clean && make -j4 && make -j4 check && make install"
        end
        ENV['CC'] = cc
        ENV['LD'] = ld
        ENV['AR'] = ar
        ENV['CFLAGS'] = cflags
        ENV['LDFLAGS'] = ldflags
      end
      spec.linker.flags << "#{spec.build_dir}/lib/libsodium.a"
      spec.cc.include_paths << "#{spec.build_dir}/include"
      build.cc.include_paths << "#{spec.build_dir}/include"
    end
  end
  spec.add_dependency 'mruby-errno'
  spec.add_dependency 'mruby-secure-compare'
end
