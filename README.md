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

ARP paket se sastoji od Ethernet frame headera i ARP headera. Dužina Ethernet frame headera je 14 bajtova, dok je dužina ARP headera 28 bajtova. Informacije vezane za Address Resolution Protocol nalaze se upravo u ovom dijelu.
U ARP paketu, EtherType u Ethernet zaglavlju ima vrijednost 0x0806. Ostali dijelovi Ethernet headera isti su kao i kod drugih Ethernet paketa.
ARP header sadrži više različitih polja. Ispod se nalaze navedeni dijelovi ARP headera, jedan po jedan.
<img width="1131" height="582" alt="image" src="https://github.com/user-attachments/assets/bc90bd7e-3b97-43aa-a1e2-2c374282ac84" />

Kao što se može vidjeti u formatu ARP paketa, ARP header se sastoji od više različitih polja. Njihovi nazivi su:


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



## Opis projekta i popis signala

U ovom projektu implementira se VHDL modul ARP Responder, čija je uloga da odgovori na ARP upite za rezoluciju MAC adrese lokalnog čvora. Modul prima Ethernet/ARP okvire putem Avalon-ST interfejsa i generiše odgovarajući ARP reply kada je ciljna IP adresa jednaka adresi konfigurisanog čvora.
IP adresa i MAC adresa uređaja definišu se kao generički parametri prilikom instanciranja modula, što omogućava jednostavnu integraciju u različite mrežne konfiguracije. Komunikacija preko ulaznih i izlaznih portova odvija se korištenjem ready/valid rukovanja, koje obezbjeđuje pouzdan prijenos podataka kroz tok.
U nastavku je prikazan popis svih signala korištenih u ARP Responder modulu: 
- `clock`: Takt signal
- `reset`: Reset signal (aktivna visoka vrednost)
- `in_data[7:0]`: Ulazni podaci (bajt po bajt)
- `in_valid`: Validnost ulaznih podataka
- `in_sop`: Start of Packet za ulaz
- `in_eop`: End of Packet za ulaz
- `in_ready`: Ready signal za ulaz (modul spreman za prijem)
- `out_data[7:0]`: Izlazni podaci (bajt po bajt)
- `out_valid`: Validnost izlaznih podataka
- `out_sop`: Start of Packet za izlaz
- `out_eop`: End of Packet za izlaz
- `out_ready`: Ready signal za izlaz (primalac spreman).

## Scenariji za testiranje

| Scenarij | Opis | Očekivani rezultat |
|----------|------|-------------------|
| **1. Validan ARP Request za našu IP** | Primi ARP request za konfiguriranu IP adresu | Pošalje ARP Reply sa našom MAC adresom |
| **2. ARP Request za drugu IP** | Primi ARP request za neku drugu IP adresu | Ne šalje odgovor i vraća se u IDLE stanje |
| **3. Non-ARP paket** | Primi Ethernet okvir koji nije ARP | Ignoriše paket i vraća se u IDLE stanje |
| **4. ARP Reply (ne Request)** | Primi ARP Reply umjesto Requesta | Ignoriše okvir i vraća se u IDLE stanje |
| **5. Backpressure test** | `out_ready = '0'` tokom slanja odgovora | Pauzira slanje dok `out_ready` ne postane `'1'` |

## WaveDrom dijagram
Wavedrom dijagram je kreiran pomoću WaveDrom alata i prikazan je u fajlu `waveform.json`. Dijagrami pokrivaju sljedeće scenarije:

## FSM (Finite State Machine) dizajn
FSM dijagram je kreiran pomoću draw.io alata i sačuvan u fajlu `fsm_diagram.drawio`.

### Opis stanja FSM-a


## VHDL implementacija

VHDL kod je implementiran u fajlu `arp_responder.vhd`. Modul implementira:

## Verifikacija pomoću simulacijskog alata ModelSim

## Zaključak

## Literatura
[1] Avalon Interface Specification, Intel Quartus Prime Design Suite 20.1, v2022.01.24



