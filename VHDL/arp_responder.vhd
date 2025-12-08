LIBRARY IEEE;
USE IEEE.STD_LOGIC_1164.ALL;
USE IEEE.NUMERIC_STD.ALL;

ENTITY arp_responder IS
    GENERIC (
       IP_ADDRESS  : STD_LOGIC_VECTOR(31 DOWNTO 0) := X"C0A80164";
MAC_ADDRESS : STD_LOGIC_VECTOR(47 DOWNTO 0) := X"001122334455" 
    );
    PORT (
        clock     : IN  STD_LOGIC;
        reset     : IN  STD_LOGIC;
        -- Avalon-ST Sink (Input)
        in_data   : IN  STD_LOGIC_VECTOR(7 DOWNTO 0);
        in_valid  : IN  STD_LOGIC;
        in_sop    : IN  STD_LOGIC;
        in_eop    : IN  STD_LOGIC;
        in_ready  : OUT STD_LOGIC;
        -- Avalon-ST Source (Output)
        out_data  : OUT STD_LOGIC_VECTOR(7 DOWNTO 0);
        out_valid : OUT STD_LOGIC;
        out_sop   : OUT STD_LOGIC;
        out_eop   : OUT STD_LOGIC;
        out_ready : IN  STD_LOGIC
    );
END arp_responder;

ARCHITECTURE rtl OF arp_responder IS

    -- Konstante za ARP protokol
    CONSTANT ETHERTYPE_ARP    : STD_LOGIC_VECTOR(15 DOWNTO 0) := X"0806";
    CONSTANT HW_TYPE_ETH      : STD_LOGIC_VECTOR(15 DOWNTO 0) := X"0001";
    CONSTANT PROTO_TYPE_IPV4  : STD_LOGIC_VECTOR(15 DOWNTO 0) := X"0800";
    CONSTANT HW_LEN           : STD_LOGIC_VECTOR(7 DOWNTO 0)  := X"06";
    CONSTANT PROTO_LEN        : STD_LOGIC_VECTOR(7 DOWNTO 0)  := X"04";
    CONSTANT ARP_REQUEST      : STD_LOGIC_VECTOR(15 DOWNTO 0) := X"0001";
    CONSTANT ARP_REPLY        : STD_LOGIC_VECTOR(15 DOWNTO 0) := X"0002";
    CONSTANT BROADCAST_MAC    : STD_LOGIC_VECTOR(47 DOWNTO 0) := X"FFFFFFFFFFFF";
    
    -- ARP paket veličina
    CONSTANT ARP_FRAME_SIZE   : INTEGER := 42;
    
    -- FSM stanja
    TYPE state_type IS (
        IDLE,
        RECEIVE_FRAME,
        CHECK_ARP,
        SEND_REPLY,
        WAIT_EOP
    );
    SIGNAL state : state_type;
    
    -- Bafer za primljeni okvir
    TYPE frame_buffer_type IS ARRAY (0 TO ARP_FRAME_SIZE-1) OF STD_LOGIC_VECTOR(7 DOWNTO 0);
    SIGNAL rx_buffer : frame_buffer_type;
    
    -- Brojač bajtova
    SIGNAL byte_counter : INTEGER RANGE 0 TO ARP_FRAME_SIZE;
    SIGNAL tx_counter   : INTEGER RANGE 0 TO ARP_FRAME_SIZE;
    
    -- Signali za validaciju
    SIGNAL is_valid_arp_request : STD_LOGIC;
    SIGNAL is_for_us            : STD_LOGIC;
    
    -- Bafer za odgovor
    SIGNAL tx_buffer : frame_buffer_type;
    
    -- Interni signali
    SIGNAL in_ready_i  : STD_LOGIC;
    SIGNAL out_valid_i : STD_LOGIC;

BEGIN

    -- Proces za validaciju ARP zahtjeva
    validate_arp: PROCESS(rx_buffer, byte_counter)
        VARIABLE ethertype   : STD_LOGIC_VECTOR(15 DOWNTO 0);
        VARIABLE hw_type     : STD_LOGIC_VECTOR(15 DOWNTO 0);
        VARIABLE proto_type  : STD_LOGIC_VECTOR(15 DOWNTO 0);
        VARIABLE operation   : STD_LOGIC_VECTOR(15 DOWNTO 0);
        VARIABLE target_ip   : STD_LOGIC_VECTOR(31 DOWNTO 0);
    BEGIN
        is_valid_arp_request <= '0';
        is_for_us <= '0';
        
        IF byte_counter = ARP_FRAME_SIZE THEN
            -- Ekstrahuj polja iz primljenog okvira
            ethertype  := rx_buffer(12) & rx_buffer(13);
            hw_type    := rx_buffer(14) & rx_buffer(15);
            proto_type := rx_buffer(16) & rx_buffer(17);
            operation  := rx_buffer(20) & rx_buffer(21);
            target_ip  := rx_buffer(38) & rx_buffer(39) & rx_buffer(40) & rx_buffer(41);
            
            -- Provjeri da li je validan ARP request
            IF ethertype = ETHERTYPE_ARP AND
               hw_type = HW_TYPE_ETH AND
               proto_type = PROTO_TYPE_IPV4 AND
               rx_buffer(18) = HW_LEN AND
               rx_buffer(19) = PROTO_LEN AND
               operation = ARP_REQUEST THEN
                is_valid_arp_request <= '1';
                
                -- Provjeri da li je zahtjev za našu IP adresu
                IF target_ip = IP_ADDRESS THEN
                    is_for_us <= '1';
                END IF;
            END IF;
        END IF;
    END PROCESS;

    -- Glavni FSM proces
    fsm_proc: PROCESS(clock, reset)
    BEGIN
        IF reset = '1' THEN
            state <= IDLE;
            byte_counter <= 0;
            tx_counter <= 0;
            in_ready_i <= '1';
            out_valid_i <= '0';
            out_sop <= '0';
            out_eop <= '0';
            out_data <= (OTHERS => '0');
            
        ELSIF rising_edge(clock) THEN
            -- Default vrijednosti
            out_sop <= '0';
            out_eop <= '0';
            
            CASE state IS
                
                WHEN IDLE =>
                    in_ready_i <= '1';
                    out_valid_i <= '0';
                    byte_counter <= 0;
                    tx_counter <= 0;
                    
                    -- Čekaj početak novog okvira
                    IF in_valid = '1' AND in_sop = '1' THEN
                        rx_buffer(0) <= in_data;
                        byte_counter <= 1;
                        state <= RECEIVE_FRAME;
                    END IF;
                
                WHEN RECEIVE_FRAME =>
                    in_ready_i <= '1';
                    
                    IF in_valid = '1' THEN
                        -- Spremi primljeni bajt
                        IF byte_counter < ARP_FRAME_SIZE THEN
                            rx_buffer(byte_counter) <= in_data;
                            byte_counter <= byte_counter + 1;
                        END IF;
                        
                        -- Kraj okvira
                        IF in_eop = '1' THEN
                            state <= CHECK_ARP;
                            in_ready_i <= '0';
                        END IF;
                    END IF;
                
                WHEN CHECK_ARP =>
                    in_ready_i <= '0';
                    
                    IF is_valid_arp_request = '1' AND is_for_us = '1' THEN
                        -- Pripremi ARP reply
                        -- Dest MAC = Sender MAC iz requesta
                        tx_buffer(0) <= rx_buffer(22);
                        tx_buffer(1) <= rx_buffer(23);
                        tx_buffer(2) <= rx_buffer(24);
                        tx_buffer(3) <= rx_buffer(25);
                        tx_buffer(4) <= rx_buffer(26);
                        tx_buffer(5) <= rx_buffer(27);
                        
                        -- Src MAC = naša MAC adresa
                        tx_buffer(6)  <= MAC_ADDRESS(47 DOWNTO 40);
                        tx_buffer(7)  <= MAC_ADDRESS(39 DOWNTO 32);
                        tx_buffer(8)  <= MAC_ADDRESS(31 DOWNTO 24);
                        tx_buffer(9)  <= MAC_ADDRESS(23 DOWNTO 16);
                        tx_buffer(10) <= MAC_ADDRESS(15 DOWNTO 8);
                        tx_buffer(11) <= MAC_ADDRESS(7 DOWNTO 0);
                        
                        -- EtherType = ARP
                        tx_buffer(12) <= ETHERTYPE_ARP(15 DOWNTO 8);
                        tx_buffer(13) <= ETHERTYPE_ARP(7 DOWNTO 0);
                        
                        -- HW Type
                        tx_buffer(14) <= HW_TYPE_ETH(15 DOWNTO 8);
                        tx_buffer(15) <= HW_TYPE_ETH(7 DOWNTO 0);
                        
                        -- Proto Type
                        tx_buffer(16) <= PROTO_TYPE_IPV4(15 DOWNTO 8);
                        tx_buffer(17) <= PROTO_TYPE_IPV4(7 DOWNTO 0);
                        
                        -- HW Len, Proto Len
                        tx_buffer(18) <= HW_LEN;
                        tx_buffer(19) <= PROTO_LEN;
                        
                        -- Operation = ARP Reply
                        tx_buffer(20) <= ARP_REPLY(15 DOWNTO 8);
                        tx_buffer(21) <= ARP_REPLY(7 DOWNTO 0);
                        
                        -- Sender MAC = naša MAC
                        tx_buffer(22) <= MAC_ADDRESS(47 DOWNTO 40);
                        tx_buffer(23) <= MAC_ADDRESS(39 DOWNTO 32);
                        tx_buffer(24) <= MAC_ADDRESS(31 DOWNTO 24);
                        tx_buffer(25) <= MAC_ADDRESS(23 DOWNTO 16);
                        tx_buffer(26) <= MAC_ADDRESS(15 DOWNTO 8);
                        tx_buffer(27) <= MAC_ADDRESS(7 DOWNTO 0);
                        
                        -- Sender IP = naša IP
                        tx_buffer(28) <= IP_ADDRESS(31 DOWNTO 24);
                        tx_buffer(29) <= IP_ADDRESS(23 DOWNTO 16);
                        tx_buffer(30) <= IP_ADDRESS(15 DOWNTO 8);
                        tx_buffer(31) <= IP_ADDRESS(7 DOWNTO 0);
                        
                        -- Target MAC = Sender MAC iz requesta
                        tx_buffer(32) <= rx_buffer(22);
                        tx_buffer(33) <= rx_buffer(23);
                        tx_buffer(34) <= rx_buffer(24);
                        tx_buffer(35) <= rx_buffer(25);
                        tx_buffer(36) <= rx_buffer(26);
                        tx_buffer(37) <= rx_buffer(27);
                        
                        -- Target IP = Sender IP iz requesta
                        tx_buffer(38) <= rx_buffer(28);
                        tx_buffer(39) <= rx_buffer(29);
                        tx_buffer(40) <= rx_buffer(30);
                        tx_buffer(41) <= rx_buffer(31);
                        
                        tx_counter <= 0;
                        state <= SEND_REPLY;
                    ELSE
                        -- Nije validan ARP request ili nije za nas
                        state <= IDLE;
                    END IF;
                
                WHEN SEND_REPLY =>
                    in_ready_i <= '0';
                    out_valid_i <= '1';
                    out_data <= tx_buffer(tx_counter);
                    
                    -- Start of packet
                    IF tx_counter = 0 THEN
                        out_sop <= '1';
                    END IF;
                    
                    -- End of packet
                    IF tx_counter = ARP_FRAME_SIZE - 1 THEN
                        out_eop <= '1';
                    END IF;
                    
                    -- Pomakni na sljedeći bajt kada je ready
                    IF out_ready = '1' THEN
                        IF tx_counter = ARP_FRAME_SIZE - 1 THEN
                            state <= WAIT_EOP;
                            out_valid_i <= '0';
                        ELSE
                            tx_counter <= tx_counter + 1;
                        END IF;
                    END IF;
                
                WHEN WAIT_EOP =>
                    -- Čekaj da se završi slanje prije povratka u IDLE
                    out_valid_i <= '0';
                    out_sop <= '0';
                    out_eop <= '0';
                    state <= IDLE;
                
                WHEN OTHERS =>
                    state <= IDLE;
                    
            END CASE;
        END IF;
    END PROCESS;
    
    -- Izlazni signali
    in_ready <= in_ready_i;
    out_valid <= out_valid_i;

END rtl;
