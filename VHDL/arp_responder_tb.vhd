LIBRARY IEEE;
USE IEEE.STD_LOGIC_1164.ALL;
USE IEEE.NUMERIC_STD.ALL;

ENTITY arp_responder_tb IS
END arp_responder_tb;

ARCHITECTURE behavior OF arp_responder_tb IS

    -- Komponenta pod testom
    COMPONENT arp_responder
        GENERIC (
            IP_ADDRESS  : STD_LOGIC_VECTOR(31 DOWNTO 0);
            MAC_ADDRESS : STD_LOGIC_VECTOR(47 DOWNTO 0)
        );
        PORT (
            clock     : IN  STD_LOGIC;
            reset     : IN  STD_LOGIC;
            in_data   : IN  STD_LOGIC_VECTOR(7 DOWNTO 0);
            in_valid  : IN  STD_LOGIC;
            in_sop    : IN  STD_LOGIC;
            in_eop    : IN  STD_LOGIC;
            in_ready  : OUT STD_LOGIC;
            out_data  : OUT STD_LOGIC_VECTOR(7 DOWNTO 0);
            out_valid : OUT STD_LOGIC;
            out_sop   : OUT STD_LOGIC;
            out_eop   : OUT STD_LOGIC;
            out_ready : IN  STD_LOGIC
        );
    END COMPONENT;

    -- Testne konstante
    CONSTANT TEST_IP  : STD_LOGIC_VECTOR(31 DOWNTO 0) := X"C0A80101"; -- 192.168.1.1
    CONSTANT TEST_MAC : STD_LOGIC_VECTOR(47 DOWNTO 0) := X"001122334455";
    
    CONSTANT CLK_PERIOD : TIME := 10 ns;
    
    -- Signali
    SIGNAL clock     : STD_LOGIC := '0';
    SIGNAL reset     : STD_LOGIC := '1';
    SIGNAL in_data   : STD_LOGIC_VECTOR(7 DOWNTO 0) := (OTHERS => '0');
    SIGNAL in_valid  : STD_LOGIC := '0';
    SIGNAL in_sop    : STD_LOGIC := '0';
    SIGNAL in_eop    : STD_LOGIC := '0';
    SIGNAL in_ready  : STD_LOGIC;
    SIGNAL out_data  : STD_LOGIC_VECTOR(7 DOWNTO 0);
    SIGNAL out_valid : STD_LOGIC;
    SIGNAL out_sop   : STD_LOGIC;
    SIGNAL out_eop   : STD_LOGIC;
    SIGNAL out_ready : STD_LOGIC := '1';
    
    -- ARP Request frame (42 bytes)
    TYPE frame_type IS ARRAY (0 TO 41) OF STD_LOGIC_VECTOR(7 DOWNTO 0);
    SIGNAL arp_request : frame_type := (
        -- Dest MAC (broadcast)
        X"FF", X"FF", X"FF", X"FF", X"FF", X"FF",
        -- Src MAC (sender)
        X"AA", X"BB", X"CC", X"DD", X"EE", X"FF",
        -- EtherType (ARP)
        X"08", X"06",
        -- HW Type (Ethernet)
        X"00", X"01",
        -- Proto Type (IPv4)
        X"08", X"00",
        -- HW Len, Proto Len
        X"06", X"04",
        -- Operation (Request)
        X"00", X"01",
        -- Sender MAC
        X"AA", X"BB", X"CC", X"DD", X"EE", X"FF",
        -- Sender IP (192.168.1.100)
        X"C0", X"A8", X"01", X"64",
        -- Target MAC (zeros)
        X"00", X"00", X"00", X"00", X"00", X"00",
        -- Target IP (192.168.1.1 - our IP)
        X"C0", X"A8", X"01", X"01"
    );

BEGIN

    -- Instanciranje komponente
    uut: arp_responder
        GENERIC MAP (
            IP_ADDRESS  => TEST_IP,
            MAC_ADDRESS => TEST_MAC
        )
        PORT MAP (
            clock     => clock,
            reset     => reset,
            in_data   => in_data,
            in_valid  => in_valid,
            in_sop    => in_sop,
            in_eop    => in_eop,
            in_ready  => in_ready,
            out_data  => out_data,
            out_valid => out_valid,
            out_sop   => out_sop,
            out_eop   => out_eop,
            out_ready => out_ready
        );

    -- Clock generator
    clock_proc: PROCESS
    BEGIN
        clock <= '0';
        WAIT FOR CLK_PERIOD/2;
        clock <= '1';
        WAIT FOR CLK_PERIOD/2;
    END PROCESS;

    -- Stimulus proces
    stim_proc: PROCESS
    BEGIN
        -- Reset
        reset <= '1';
        WAIT FOR CLK_PERIOD * 5;
        reset <= '0';
        WAIT FOR CLK_PERIOD * 2;
        
        -- Pošalji ARP request
        FOR i IN 0 TO 41 LOOP
            WAIT UNTIL rising_edge(clock);
            in_valid <= '1';
            in_data <= arp_request(i);
            
            IF i = 0 THEN
                in_sop <= '1';
            ELSE
                in_sop <= '0';
            END IF;
            
            IF i = 41 THEN
                in_eop <= '1';
            ELSE
                in_eop <= '0';
            END IF;
        END LOOP;
        
        WAIT UNTIL rising_edge(clock);
        in_valid <= '0';
        in_sop <= '0';
        in_eop <= '0';
        
        -- Čekaj i provjeri odgovor
        WAIT FOR CLK_PERIOD * 100;
        
        -- Završi simulaciju
        REPORT "Simulation finished" SEVERITY NOTE;
        WAIT;
    END PROCESS;

END behavior;
