current_dir=$(pwd)
echo "$current_dir"

# build xen sdk
rm -rf  XenServer-SDK
unzip XenServer-7.4.0-SDK.zip
cd XenServer-SDK/libxenserver/src
make DESTDIR=${current_dir}/3rd install

# build json
cd $current_dir
rm jsoncpp
tar zxvf jsoncpp.tar.gz
cd jsoncpp && mkdir build && cd build
cmake -DCMAKE_INSTALL_LIBDIR=${current_dir}/3rd/lib -DCMAKE_INSTALL_INCLUDEDIR=${current_dir}/3rd/include ..
make install

# build test
rm -rf $current_dir/xc/build
cd $current_dir/xc && mkdir xc && cd xc
cmake .. && make
