# ARP Responder

## Uvod

ARP (Address Resolution Protocol) je protokol koji povezuje logičko adresiranje na mrežnom sloju (IPv4 adrese) sa fizičkim adresiranjem na podatkovnom sloju (MAC adrese) u lokalnoj mreži. U tipičnoj Ethernet LAN mreži, Ethernet okvir se isporučuje na osnovu MAC adrese odredišta, dok aplikacije i protokoli viših slojeva (npr. TCP/UDP) komuniciraju korištenjem IP adresa.

Kada čvor želi poslati IP paket ka određenoj IPv4 adresi u istoj lokalnoj mreži, on mora znati kojoj MAC adresi ta IP adresa pripada. Ako tražena IP adresa nije prisutna u lokalnoj ARP tabeli (ARP cache), čvor inicira ARP postupak razrješenja adrese (engl. address resolution):

1. Generiše se ARP Request – broadcast Ethernet okvir u kojem se navodi:
   - IP adresa čvora čija se MAC adresa traži,
   - IP i MAC adresa pošiljaoca zahtjeva.
2. Svi uređaji u lokalnoj mreži primaju ARP Request, ali **odgovara samo onaj čija IP adresa odgovara traženoj adresi**.
3. Taj uređaj šalje ARP Reply – unicast Ethernet okvir koji sadrži:
   - svoju MAC adresu,
   - svoju IP adresu (kao potvrdu),
   - IP/MAC adrese pošiljaoca zahtjeva u odgovarajućim poljima.
4. Pošiljalac ažurira svoju ARP tabelu, upisuje par (IP, MAC) i omogućava slanje IP paketa ka tom odredištu koristeći dobijenu MAC adresu.

Na ovaj način ARP obezbjeđuje osnovnu funkcionalnost mapiranja IP → MAC u lokalnoj mreži, bez koje IPv4 saobraćaj ne bi mogao biti isporučen na podatkovnom nivou.

## ARP protokol

ARP poruke se prenose unutar Ethernet okvira, pri čemu se u polju EtherType nalazi vrijednost `0x0806`, što označava da se u polju podataka (payload) nalazi ARP okvir. ARP okvir sadrži sljedeća ključna polja:

- **Hardware type (HTYPE)** – tip fizičkog interfejsa; za Ethernet je najčešće vrijednost `1`.
- **Protocol type (PTYPE)** – identifikator protokola višeg sloja; za IPv4 se koristi vrijednost `0x0800`.
- **Hardware address length (HLEN)** – dužina hardverske (MAC) adrese u oktetima; za Ethernet je `6`.
- **Protocol address length (PLEN)** – dužina IP adrese u oktetima; za IPv4 je `4`.
- **Opcode** – tip ARP poruke:
  - `1` – ARP Request,
  - `2` – ARP Reply.
- **Sender hardware address (SHA)** – MAC adresa pošiljaoca ARP poruke.
- **Sender protocol address (SPA)** – IP adresa pošiljaoca ARP poruke.
- **Target hardware address (THA)** – MAC adresa odredišta (kod ARP Requesta se često stavlja nula, jer još nije poznata).
- **Target protocol address (TPA)** – IP adresa odredišta čija se MAC adresa traži.

Kombinacijom ovih polja, ARP omogućava da čvor jednoznačno identifikuje ko traži adresu (sender) i za koju IP adresu (target) želi da dobije MAC adresu.
Na narednoj slici prikazan je proces ARP komunikacije, uključujući ARP request i ARP reply:
<img width="987" height="799" alt="image" src="https://github.com/user-attachments/assets/bd80100d-f5b2-4fc2-bf94-2921d3f7d430" />

## ARP Paket

ARP paket se sastoji od Ethernet frame headera i ARP headera. Dužina Ethernet frame headera je 14 bajtova, dok je dužina ARP headera 28 bajtova. Informacije vezane za Address Resolution Protocol nalaze se upravo u ovom dijelu.
U ARP paketu, EtherType u Ethernet zaglavlju ima vrijednost 0x0806. Ostali dijelovi Ethernet headera isti su kao i kod drugih Ethernet paketa.
ARP header sadrži više različitih polja. Ispod se nalaze navedeni dijelovi ARP headera, jedan po jedan.
<img width="1131" height="582" alt="image" src="https://github.com/user-attachments/assets/bc90bd7e-3b97-43aa-a1e2-2c374282ac84" />

Kao što se može vidjeti u formatu ARP paketa, ARP header se sastoji od više različitih polja. Njihovi nazivi su:

Hardware Type

Protocol Type

Hardware Address Length

Protocol Address Length

Operation Code

Source MAC Address

Source Protocol Address (IP)

Target MAC Address

Target Protocol Address (IP)



## Popis signala

Ulazni signali:
| Signal      | Tip | Opis                                 |
| ----------- | --- | ------------------------------------ |
| `clock`     | IN  | Sistemski takt                       |
| `reset`     | IN  | Reset modula                         |
| `in_data`   | IN  | Ulazni bajt Ethernet rama            |
| `in_valid`  | IN  | Ulazni bajt je ispravan              |
| `in_sop`    | IN  | Početak paketa                       |
| `in_eop`    | IN  | Kraj paketa                          |
| `in_ready`  | OUT | Modul može primiti novi bajt         |
| `out_ready` | IN  | Spoljni modul spreman da primi izlaz |

Izlazni signali: 
| Signal      | Tip | Opis                      |
| ----------- | --- | ------------------------- |
| `out_data`  | OUT | Bajt po bajt ARP odgovora |
| `out_valid` | OUT | Izlazni podatak je važeći |
| `out_sop`   | OUT | Početak ARP odgovora      |
| `out_eop`   | OUT | Kraj ARP odgovora         |


