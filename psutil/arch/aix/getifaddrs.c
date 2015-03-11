/*! This file was copied from https://lists.samba.org/archive/samba-technical/2009-February/063079.html !*/

#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>

#include "ifaddrs.h"

/********************************************************************
 *** NOTE: this generic version written specifically for AIX 5.3  ***
 ********************************************************************/

#define MAX(x,y) ((x)>(y)?(x):(y))
#define SIZE(p) MAX((p).sa_len,sizeof(p))


static struct sockaddr *
sa_dup (struct sockaddr *sa1)
{
  struct sockaddr *sa2;
  size_t sz = sa1->sa_len;
  sa2 = (struct sockaddr *) calloc(1,sz);
  memcpy(sa2,sa1,sz);
  return(sa2);
}


void freeifaddrs (struct ifaddrs *ifp)
{
  if (NULL == ifp) return;
  free(ifp->ifa_name);
  free(ifp->ifa_addr);
  free(ifp->ifa_netmask);
  free(ifp->ifa_dstaddr);
  freeifaddrs(ifp->ifa_next);
  free(ifp);
}


int getifaddrs (struct ifaddrs **ifap)
{
  int  sd, ifsize;
  char *ccp, *ecp;
  struct ifconf ifc;
  struct ifreq *ifr;
  struct ifaddrs *cifa = NULL; /* current */
  struct ifaddrs *pifa = NULL; /* previous */
  const size_t IFREQSZ = sizeof(struct ifreq);

  sd = socket(AF_INET, SOCK_DGRAM, 0);

  *ifap = NULL;

  /* find how much memory to allocate for the SIOCGIFCONF call */
  if (ioctl(sd, SIOCGSIZIFCONF, (caddr_t)&ifsize) < 0) return(-1);

  ifc.ifc_req = (struct ifreq *) calloc(1,ifsize);
  ifc.ifc_len = ifsize;

  if (ioctl(sd, SIOCGIFCONF, &ifc) < 0) return(-1);

  ccp = (char *)ifc.ifc_req;
  ecp = ccp + ifsize;

  while (ccp < ecp) {

    ifr = (struct ifreq *) ccp;
    ifsize = sizeof(ifr->ifr_name) + SIZE(ifr->ifr_addr);
    cifa = (struct ifaddrs *) calloc(1, sizeof(struct ifaddrs));
    cifa->ifa_next = NULL;
    cifa->ifa_name = strdup(ifr->ifr_name);

    if (pifa == NULL) *ifap = cifa; /* first one */
    else     pifa->ifa_next = cifa;

    if (ioctl(sd, SIOCGIFADDR, ifr, IFREQSZ) < 0) return(-1);
    cifa->ifa_addr = sa_dup(&ifr->ifr_addr);

    if (ioctl(sd, SIOCGIFNETMASK, ifr, IFREQSZ) < 0) return(-1);
    cifa->ifa_netmask = sa_dup(&ifr->ifr_addr);

    cifa->ifa_flags = 0;
    cifa->ifa_dstaddr = NULL;

    if (0 == ioctl(sd, SIOCGIFFLAGS, ifr)) /* optional */
      cifa->ifa_flags = ifr->ifr_flags;

    if (ioctl(sd, SIOCGIFDSTADDR, ifr, IFREQSZ) < 0) {
      if (0 == ioctl(sd, SIOCGIFBRDADDR, ifr, IFREQSZ))
         cifa->ifa_dstaddr = sa_dup(&ifr->ifr_addr);
    }
    else cifa->ifa_dstaddr = sa_dup(&ifr->ifr_addr);

    pifa = cifa;
    ccp += ifsize;
  }
  return 0;
}