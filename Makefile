SPECFILE := $(shell ls *.spec)
PACOTE := $(shell awk '/define name/ { print $$3 }' ${SPECFILE})
VERSAO := $(shell awk '/define version/ { print $$3 }' ${SPECFILE})
RELEASE := $(shell awk '/define release/ { print $$3 }' ${SPECFILE})


build_area := ${PWD}/build/rpm

all: clean
	mkdir -p build/${PACOTE}-${VERSAO}/src
	mkdir -p build/rpm/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	cp -a src/* build/${PACOTE}-${VERSAO}/src
	cp CHANGELOG.md LICENSE build/${PACOTE}-${VERSAO}
	tar -czvpf ${build_area}/SOURCES/${PACOTE}-${VERSAO}.tar.gz -C build --exclude=.git ${PACOTE}-${VERSAO}
	rpmbuild -ba --define "_topdir ${build_area}" --clean ${SPECFILE}
	mv ${build_area}/RPMS/x86_64/${PACOTE}-${VERSAO}-${RELEASE}.*.rpm .
	mv ${build_area}/SRPMS/${PACOTE}-${VERSAO}-${RELEASE}.src.rpm .

.PHONY: clean

clean:
	rm -rf build
	find . -name \*.pyc -exec rm -f {} \;
