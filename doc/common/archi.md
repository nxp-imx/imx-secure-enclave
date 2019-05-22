architecture
============

Seco features are provided to user applications through following software components:
- **SHE/HSM firmware** : FW running implementing SHE and/or HSM features. e.g. the SECO core of the i.MX8. This firwmare waits for commands sent on dedicated messaging units (MU) by cores running user applications.
- **seco kernel driver** : On Linux systems this driver is in charge of:
	- performing physical read/writes on MU and handling interrupts
	- formatting and parsing messages (this code is OS-independent)
	- providing API to user-space through ioctl.
- **seco_libs** : user-space libraries performing the ioctl calls and providing C functions that can be called by user applications.

APIs provided to applications by seco_libs are the same than the ones implemented in the generic part of the driver. ioctls are used to convey functions parameters from user to kernel.

The generic (OS-independent) part of the kernel is in charge of formatting and parsing SECO messages. It is written in such a way that there is no direct dependency to any OS.

An OS abstraction layer implements these OS-specific functionalities and is mainly in charge of MU registers accesses and interrupts management.

\dot
digraph {
fontname=Helvetica;
node[fontname=Helvetica];
label="SECO API architecture";
rankdir=LR;
ordering=out;

subgraph cluster2 {
  shape=Mrecord
  label="Linux user space"
  apps[shape=Mrecord, label="<sheapp>SHE application|<hsmapp>HSM application|<nvmapp>NVM manager", rank=source];
  subgraph cluster0 {
    shape="box";
    label="seco_libs";
    node[shape="record"];
    secolib[label="<shelib> SHE lib |<hsmlib> HSM lib|<nvmlib> NVM lib"];
  }
}

subgraph cluster1 {
  shape=Mrecord;
  label="Linux kernel";
  subgraph cluster3 {
    shape="box";
    label="SECO driver";
    node[shape="record"];
    seco_drv[label="{{<shedrv> SHE ioctls |<hsmdrv> HSM ioctls|<nvmdrv> NVM ioctls}|generic\ndriver|<osabs>OS\nabstraction}"];
  }
}

mu[shape=Mrecord, label="<mu1> MU|<mu2> MU|<mu3> MU"];

seco[shape=box, label="SHE/HSM firmware", rank="sink"];

apps:sheapp -> secolib:shelib;
apps:hsmapp -> secolib:hsmlib;
apps:nvmapp -> secolib:nvmlib;
secolib:shelib -> seco_drv:shedrv [label="/dev/seco_she"];
secolib:hsmlib -> seco_drv:hsmdrv [label="/dev/seco_hsm"];
secolib:nvmlib -> seco_drv:nvmdrv [label="/dev/seco_nvm"];
seco_drv:osabs -> mu:mu1;
seco_drv:osabs -> mu:mu2;
seco_drv:osabs -> mu:mu3;
mu:mu1 -> seco;
mu:mu2 -> seco;
mu:mu3 -> seco;
}
\enddot
