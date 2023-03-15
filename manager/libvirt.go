package manager

import "github.com/digitalocean/go-libvirt"

const poolXML string = `
<pool type="dir">
<name>virtimages</name>
<target>
  <path>/home/darko/go/src/github.com/ultravioletrs/cocosvm/cmd/manager/img</path>
</target>
</pool>
`
const volXML string = `
<volume>
<name>boot.img</name>
<allocation>0</allocation>
<capacity unit="T">1</capacity>
<target>
  <path>/home/darko/go/src/github.com/ultravioletrs/cocosvm/cmd/manager/img/boot.img</path>
  <permissions>
	<owner>107</owner>
	<group>107</group>
	<mode>0744</mode>
	<label>virt_image_t</label>
  </permissions>
</target>
</volume>
`

const domXML string = `
<domain type='qemu'>
  <name>QEmu-alpine-standard-x86_64</name>
  <uuid>c7a5fdbd-cdaf-9455-926a-d65c16db1809</uuid>
  <memory>219200</memory>
  <currentMemory>219200</currentMemory>
  <vcpu>2</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <boot dev='cdrom'/>
  </os>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='cdrom'>
      <source file='/home/darko/go/src/github.com/ultravioletrs/cocosvm/cmd/manager/iso/alpine-standard-3.17.2-x86_64.iso'/>
      <target dev='hdc'/>
      <readonly/>
    </disk>
    <disk type='file' device='disk'>
      <source file='/home/darko/go/src/github.com/ultravioletrs/cocosvm/cmd/manager/img/boot.img'/>
      <target dev='hda'/>
    </disk>
    <interface type='network'>
      <source network='default'/>
    </interface>
    <graphics type='vnc' port='-1'/>
  </devices>
</domain>
`

func createDomain(libvirtConn *libvirt.Libvirt, poolXML string, volXML string, domXML string) (libvirt.Domain, error) {
	pool, err := libvirtConn.StoragePoolCreateXML(poolXML, 0)
	if err != nil {
		return libvirt.Domain{}, err
	}

	vol, err := libvirtConn.StorageVolCreateXML(pool, volXML, 0)
	if err != nil {
		return libvirt.Domain{}, err
	}
	_ = vol

	dom, err := libvirtConn.DomainDefineXMLFlags(domXML, 0)
	if err != nil {
		return libvirt.Domain{}, err
	}

	err = libvirtConn.DomainCreate(dom)
	if err != nil {
		return libvirt.Domain{}, err
	}

	return dom, nil
}
