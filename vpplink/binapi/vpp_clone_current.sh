#!/bin/bash
VPP_COMMIT=9f1dbd20

if [ ! -d $1 ]; then
	git clone "https://gerrit.fd.io/r/vpp" $1
	cd $1
	git reset --hard ${VPP_COMMIT}
else
	cd $1
	git fetch "https://gerrit.fd.io/r/vpp" && git reset --hard ${VPP_COMMIT}
fi

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/87/28587/14 && git cherry-pick FETCH_HEAD # calico plugin
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/51/28651/3 && git cherry-pick FETCH_HEAD # NodeAPI fix
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/50/28650/1 && git cherry-pick FETCH_HEAD # get_node_name fix

# Policies
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/28083/9 && git cherry-pick FETCH_HEAD # ACL custom policies
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/13/28513/3 && git cherry-pick FETCH_HEAD # Calico policies
