# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "centos/7"

  (1..2).each do |i|
      config.vm.define vm_name = "ldap#{i}" do |config|
          config.vm.hostname = "ldap#{i}"
          config.vm.network :private_network, ip: "192.168.9.#{i+100}"
      end
  end

  (1..2).each do |i|
      config.vm.define vm_name = "kdc#{i}" do |config|
          config.vm.hostname = "kdc#{i}"
          config.vm.network :private_network, ip: "192.168.9.#{i+102}"
      end
  end

  config.vm.define vm_name = "client" do |config|
      config.vm.hostname = "client"
      config.vm.network :private_network, ip: "192.168.9.105"

      config.vm.provision :ansible do |ansible|
        ansible.groups = {
            "ldap" => ["ldap[1:2]"],
            "kdc"  => ["kdc[1:2]"],
        }
        ansible.playbook = "ansible/playbook.yaml"
        ansible.vault_password_file = "ansible/vault.secret"
        ansible.limit = "all"
      end
  end

end