`ifndef COCOTB_SIM
`include "sss_shared_output_buffer_cpu_regs_defines.sv"
`endif

module sss_shared_output_buffer_cpu_regs #
(
    parameter C_BASE_ADDRESS     = 32'h00000000,
    parameter C_S_AXI_DATA_WIDTH = 32,
    parameter C_S_AXI_ADDR_WIDTH = 32
)
(
    // General ports
    input clk,
    input resetn,
    // Global Registers
    input      cpu_resetn_soft,
    output reg resetn_soft,
    output reg resetn_sync,

   // Register ports
    input      [`REG_ID_BITS]      id_reg,
    input      [`REG_VERSION_BITS] version_reg,
    output reg [`REG_RESET_BITS]   reset_reg,
    input      [`REG_FLIP_BITS]    ip2cpu_flip_reg,
    output reg [`REG_FLIP_BITS]    cpu2ip_flip_reg,
    input      [`REG_DEBUG_BITS]   ip2cpu_debug_reg,
    output reg [`REG_DEBUG_BITS]   cpu2ip_debug_reg,
    input      [`REG_PKTIN_BITS]   pktin_reg,
    output reg                     pktin_reg_clear,
    input      [`REG_PKTOUT_BITS]  pktout_reg,
    output reg                     pktout_reg_clear,

    input      [`REG_PKTSTOREDPORT0_BITS]    pktstoredport0_reg,
    output reg                               pktstoredport0_reg_clear,
    input      [`REG_BYTESSTOREDPORT0_BITS]  bytesstoredport0_reg,
    output reg                               bytesstoredport0_reg_clear,
    input      [`REG_PKTREMOVEDPORT0_BITS]   pktremovedport0_reg,
    output reg                               pktremovedport0_reg_clear,
    input      [`REG_BYTESREMOVEDPORT0_BITS] bytesremovedport0_reg,
    output reg                               bytesremovedport0_reg_clear,
    input      [`REG_PKTDROPPEDPORT0_BITS]   pktdroppedport0_reg,
    output reg                               pktdroppedport0_reg_clear,
    input      [`REG_BYTESDROPPEDPORT0_BITS] bytesdroppedport0_reg,
    output reg                               bytesdroppedport0_reg_clear,
    input      [`REG_PKTINQUEUEPORT0_BITS]   pktinqueueport0_reg,
    output reg                               pktinqueueport0_reg_clear,

    input      [`REG_PKTSTOREDPORT1_BITS]    pktstoredport1_reg,
    output reg                               pktstoredport1_reg_clear,
    input      [`REG_BYTESSTOREDPORT1_BITS]  bytesstoredport1_reg,
    output reg                               bytesstoredport1_reg_clear,
    input      [`REG_PKTREMOVEDPORT1_BITS]   pktremovedport1_reg,
    output reg                               pktremovedport1_reg_clear,
    input      [`REG_BYTESREMOVEDPORT1_BITS] bytesremovedport1_reg,
    output reg                               bytesremovedport1_reg_clear,
    input      [`REG_PKTDROPPEDPORT1_BITS]   pktdroppedport1_reg,
    output reg                               pktdroppedport1_reg_clear,
    input      [`REG_BYTESDROPPEDPORT1_BITS] bytesdroppedport1_reg,
    output reg                               bytesdroppedport1_reg_clear,
    input      [`REG_PKTINQUEUEPORT1_BITS]   pktinqueueport1_reg,
    output reg                               pktinqueueport1_reg_clear,

    input      [`REG_PKTSTOREDPORT2_BITS]    pktstoredport2_reg,
    output reg                               pktstoredport2_reg_clear,
    input      [`REG_BYTESSTOREDPORT2_BITS]  bytesstoredport2_reg,
    output reg                               bytesstoredport2_reg_clear,
    input      [`REG_PKTREMOVEDPORT2_BITS]   pktremovedport2_reg,
    output reg                               pktremovedport2_reg_clear,
    input      [`REG_BYTESREMOVEDPORT2_BITS] bytesremovedport2_reg,
    output reg                               bytesremovedport2_reg_clear,
    input      [`REG_PKTDROPPEDPORT2_BITS]   pktdroppedport2_reg,
    output reg                               pktdroppedport2_reg_clear,
    input      [`REG_BYTESDROPPEDPORT2_BITS] bytesdroppedport2_reg,
    output reg                               bytesdroppedport2_reg_clear,
    input      [`REG_PKTINQUEUEPORT2_BITS]   pktinqueueport2_reg,
    output reg                               pktinqueueport2_reg_clear,

    input      [`REG_PKTSTOREDPORT3_BITS]    pktstoredport3_reg,
    output reg                               pktstoredport3_reg_clear,
    input      [`REG_BYTESSTOREDPORT3_BITS]  bytesstoredport3_reg,
    output reg                               bytesstoredport3_reg_clear,
    input      [`REG_PKTREMOVEDPORT3_BITS]   pktremovedport3_reg,
    output reg                               pktremovedport3_reg_clear,
    input      [`REG_BYTESREMOVEDPORT3_BITS] bytesremovedport3_reg,
    output reg                               bytesremovedport3_reg_clear,
    input      [`REG_PKTDROPPEDPORT3_BITS]   pktdroppedport3_reg,
    output reg                               pktdroppedport3_reg_clear,
    input      [`REG_BYTESDROPPEDPORT3_BITS] bytesdroppedport3_reg,
    output reg                               bytesdroppedport3_reg_clear,
    input      [`REG_PKTINQUEUEPORT3_BITS]   pktinqueueport3_reg,
    output reg                               pktinqueueport3_reg_clear,

    input      [`REG_PKTSTOREDPORT4_BITS]    pktstoredport4_reg,
    output reg                               pktstoredport4_reg_clear,
    input      [`REG_BYTESSTOREDPORT4_BITS]  bytesstoredport4_reg,
    output reg                               bytesstoredport4_reg_clear,
    input      [`REG_PKTREMOVEDPORT4_BITS]   pktremovedport4_reg,
    output reg                               pktremovedport4_reg_clear,
    input      [`REG_BYTESREMOVEDPORT4_BITS] bytesremovedport4_reg,
    output reg                               bytesremovedport4_reg_clear,
    input      [`REG_PKTDROPPEDPORT4_BITS]   pktdroppedport4_reg,
    output reg                               pktdroppedport4_reg_clear,
    input      [`REG_BYTESDROPPEDPORT4_BITS] bytesdroppedport4_reg,
    output reg                               bytesdroppedport4_reg_clear,
    input      [`REG_PKTINQUEUEPORT4_BITS]   pktinqueueport4_reg,
    output reg                               pktinqueueport4_reg_clear,

    // AXI Lite ports
    input                               S_AXI_ACLK,
    input                               S_AXI_ARESETN,
    input  [C_S_AXI_ADDR_WIDTH-1 : 0]   S_AXI_AWADDR,
    input                               S_AXI_AWVALID,
    input  [C_S_AXI_DATA_WIDTH-1 : 0]   S_AXI_WDATA,
    input  [C_S_AXI_DATA_WIDTH/8-1 : 0] S_AXI_WSTRB,
    input                               S_AXI_WVALID,
    input                               S_AXI_BREADY,
    input  [C_S_AXI_ADDR_WIDTH-1 : 0]   S_AXI_ARADDR,
    input                               S_AXI_ARVALID,
    input                               S_AXI_RREADY,
    output                              S_AXI_ARREADY,
    output [C_S_AXI_DATA_WIDTH-1 : 0]   S_AXI_RDATA,
    output [1 : 0]                      S_AXI_RRESP,
    output                              S_AXI_RVALID,
    output                              S_AXI_WREADY,
    output [1 :0]                       S_AXI_BRESP,
    output                              S_AXI_BVALID,
    output                              S_AXI_AWREADY
);
    // AXI4LITE signals
    reg [C_S_AXI_ADDR_WIDTH-1 : 0]      axi_awaddr;
    reg                                 axi_awready;
    reg                                 axi_wready;
    reg [1 : 0]                         axi_bresp;
    reg                                 axi_bvalid;
    reg [C_S_AXI_ADDR_WIDTH-1 : 0]      axi_araddr;
    reg                                 axi_arready;
    reg [C_S_AXI_DATA_WIDTH-1 : 0]      axi_rdata;
    reg [1 : 0]                         axi_rresp;
    reg                                 axi_rvalid;

    reg                                 resetn_sync_d;
    wire                                reg_rden;
    wire                                reg_wren;
    reg [C_S_AXI_DATA_WIDTH-1:0]        reg_data_out;
    integer                             byte_index;
    reg                                 pktin_reg_clear_d;
    reg                                 pktout_reg_clear_d;

    reg                                 pktstoredport0_reg_clear_d;
    reg                                 bytesstoredport0_reg_clear_d;
    reg                                 pktremovedport0_reg_clear_d;
    reg                                 bytesremovedport0_reg_clear_d;
    reg                                 pktdroppedport0_reg_clear_d;
    reg                                 bytesdroppedport0_reg_clear_d;
    reg                                 pktinqueueport0_reg_clear_d;

    reg                                 pktstoredport1_reg_clear_d;
    reg                                 bytesstoredport1_reg_clear_d;
    reg                                 pktremovedport1_reg_clear_d;
    reg                                 bytesremovedport1_reg_clear_d;
    reg                                 pktdroppedport1_reg_clear_d;
    reg                                 bytesdroppedport1_reg_clear_d;
    reg                                 pktinqueueport1_reg_clear_d;

    reg                                 pktstoredport2_reg_clear_d;
    reg                                 bytesstoredport2_reg_clear_d;
    reg                                 pktremovedport2_reg_clear_d;
    reg                                 bytesremovedport2_reg_clear_d;
    reg                                 pktdroppedport2_reg_clear_d;
    reg                                 bytesdroppedport2_reg_clear_d;
    reg                                 pktinqueueport2_reg_clear_d;

    reg                                 pktstoredport3_reg_clear_d;
    reg                                 bytesstoredport3_reg_clear_d;
    reg                                 pktremovedport3_reg_clear_d;
    reg                                 bytesremovedport3_reg_clear_d;
    reg                                 pktdroppedport3_reg_clear_d;
    reg                                 bytesdroppedport3_reg_clear_d;
    reg                                 pktinqueueport3_reg_clear_d;

    reg                                 pktstoredport4_reg_clear_d;
    reg                                 bytesstoredport4_reg_clear_d;
    reg                                 pktremovedport4_reg_clear_d;
    reg                                 bytesremovedport4_reg_clear_d;
    reg                                 pktdroppedport4_reg_clear_d;
    reg                                 bytesdroppedport4_reg_clear_d;
    reg                                 pktinqueueport4_reg_clear_d;

    // I/O Connections assignments
    assign S_AXI_AWREADY    = axi_awready;
    assign S_AXI_WREADY     = axi_wready;
    assign S_AXI_BRESP      = axi_bresp;
    assign S_AXI_BVALID     = axi_bvalid;
    assign S_AXI_ARREADY    = axi_arready;
    assign S_AXI_RDATA      = axi_rdata;
    assign S_AXI_RRESP      = axi_rresp;
    assign S_AXI_RVALID     = axi_rvalid;

    //Sample reset (not mandatory, but good practice)
    always @ (posedge clk) begin
        if (~resetn) begin
            resetn_sync_d  <=  1'b0;
            resetn_sync    <=  1'b0;
        end
        else begin
            resetn_sync_d  <=  resetn;
            resetn_sync    <=  resetn_sync_d;
        end
    end

    //global registers, sampling
    always @(posedge clk)
        resetn_soft <= #1 cpu_resetn_soft;

    // Implement axi_awready generation
    always @( posedge S_AXI_ACLK ) begin
        if ( S_AXI_ARESETN == 1'b0 ) begin
            axi_awready <= 1'b0;
        end
        else begin
            if (~axi_awready && S_AXI_AWVALID && S_AXI_WVALID)
                // slave is ready to accept write address when
                // there is a valid write address and write data
                // on the write address and data bus. This design
                // expects no outstanding transactions.
                axi_awready <= 1'b1;
            else
                axi_awready <= 1'b0;
        end
    end

    // Implement axi_awaddr latching
    always @( posedge S_AXI_ACLK )
        if ( S_AXI_ARESETN == 1'b0 ) begin
            axi_awaddr <= 0;
        end
        else begin
            if (~axi_awready && S_AXI_AWVALID && S_AXI_WVALID)
                // Write Address latching
                axi_awaddr <= S_AXI_AWADDR ^ C_BASE_ADDRESS;
        end

    // Implement axi_wready generation
    always @( posedge S_AXI_ACLK ) begin
        if ( S_AXI_ARESETN == 1'b0 ) begin
            axi_wready <= 1'b0;
        end
        else begin
            if (~axi_wready && S_AXI_WVALID && S_AXI_AWVALID)
                // slave is ready to accept write data when
                // there is a valid write address and write data
                // on the write address and data bus. This design
                // expects no outstanding transactions.
                axi_wready <= 1'b1;
            else
                axi_wready <= 1'b0;
        end
    end

    // Implement write response logic generation
    always @( posedge S_AXI_ACLK ) begin
        if ( S_AXI_ARESETN == 1'b0 ) begin
            axi_bvalid  <= 0;
            axi_bresp   <= 2'b0;
        end
        else begin
            if (axi_awready && S_AXI_AWVALID && ~axi_bvalid && axi_wready && S_AXI_WVALID) begin
                // indicates a valid write response is available
                axi_bvalid <= 1'b1;
                axi_bresp  <= 2'b0; // OKAY response
            end
            else begin
                if (S_AXI_BREADY && axi_bvalid)
                    //check if bready is asserted while bvalid is high)
                    //(there is a possibility that bready is always asserted high)
                    axi_bvalid <= 1'b0;
            end
        end
    end

    // Implement axi_arready generation
    always @( posedge S_AXI_ACLK ) begin
        if ( S_AXI_ARESETN == 1'b0 ) begin
            axi_arready <= 1'b0;
            axi_araddr  <= 32'b0;
        end
        else begin
            if (~axi_arready && S_AXI_ARVALID) begin
                // indicates that the slave has acceped the valid read address
                // Read address latching
                axi_arready <= 1'b1;
                axi_araddr  <= S_AXI_ARADDR ^ C_BASE_ADDRESS;
            end
            else begin
                axi_arready <= 1'b0;
            end
        end
    end

    // Implement axi_rvalid generation
    always @( posedge S_AXI_ACLK ) begin
        if ( S_AXI_ARESETN == 1'b0 ) begin
            axi_rvalid <= 0;
            axi_rresp  <= 0;
        end
        else begin
            if (axi_arready && S_AXI_ARVALID && ~axi_rvalid) begin
                // Valid read data is available at the read data bus
                axi_rvalid <= 1'b1;
                axi_rresp  <= 2'b0; // OKAY response
            end
            else if (axi_rvalid && S_AXI_RREADY) begin
                // Read data is accepted by the master
                axi_rvalid <= 1'b0;
            end
        end
    end

    // Implement memory mapped register select and write logic generation
    assign reg_wren = axi_wready && S_AXI_WVALID && axi_awready && S_AXI_AWVALID;

//////////////////////////////////////////////////////////////
// write registers
//////////////////////////////////////////////////////////////

//Write only register, clear on write (i.e. event)
    always @(posedge clk) begin
        if (!resetn_sync) begin
            reset_reg <= #1 `REG_RESET_DEFAULT;
        end
        else begin
            if (reg_wren) begin
                case (axi_awaddr)
                    //Reset Register
                    `REG_RESET_ADDR : begin
                        for ( byte_index = 0; byte_index <= (`REG_RESET_WIDTH/8-1); byte_index = byte_index +1)
                            if (S_AXI_WSTRB[byte_index] == 1)
                                reset_reg[byte_index*8 +: 8] <=  S_AXI_WDATA[byte_index*8 +: 8];
                    end
                endcase
            end
            else begin
                reset_reg <= #1 `REG_RESET_DEFAULT;
            end
        end
    end

    //R/W register, not cleared
    always @(posedge clk) begin
        if (!resetn_sync) begin
            cpu2ip_flip_reg <= #1 `REG_FLIP_DEFAULT;
            cpu2ip_debug_reg <= #1 `REG_DEBUG_DEFAULT;
        end
        else begin
            if (reg_wren) // write event
                case (axi_awaddr)
                    `REG_FLIP_ADDR : begin
                        for ( byte_index = 0; byte_index <= (`REG_FLIP_WIDTH/8-1); byte_index = byte_index +1)
                            if (S_AXI_WSTRB[byte_index] == 1)
                                cpu2ip_flip_reg[byte_index*8 +: 8] <=  S_AXI_WDATA[byte_index*8 +: 8]; //dynamic register;
                    end

                    `REG_DEBUG_ADDR : begin
                        for ( byte_index = 0; byte_index <= (`REG_DEBUG_WIDTH/8-1); byte_index = byte_index +1)
                            if (S_AXI_WSTRB[byte_index] == 1)
                                cpu2ip_debug_reg[byte_index*8 +: 8] <=  S_AXI_WDATA[byte_index*8 +: 8]; //dynamic register;
                    end
                endcase
        end
    end

    /////////////////////////
    //// end of write
    /////////////////////////

    // Implement memory mapped register select and read logic generation
    // Slave register read enable is asserted when valid address is available
    // and the slave is ready to accept the read address.

    // reg_rden control logic; temperary no extra logic here
    assign reg_rden = axi_arready & S_AXI_ARVALID & ~axi_rvalid;

    always @(*) begin
        case ( axi_araddr /*S_AXI_ARADDR ^ C_BASE_ADDRESS*/)
            //Id Register
            `REG_ID_ADDR : begin
                reg_data_out [`REG_ID_BITS] =  id_reg;
            end
            //Version Register
            `REG_VERSION_ADDR : begin
                reg_data_out [`REG_VERSION_BITS] =  version_reg;
            end
            //Flip Register
            `REG_FLIP_ADDR : begin
                reg_data_out [`REG_FLIP_BITS] =  ip2cpu_flip_reg;
            end
            //Debug Register
            `REG_DEBUG_ADDR : begin
                reg_data_out [`REG_DEBUG_BITS] =  ip2cpu_debug_reg;
            end
            //Pktin Register
            `REG_PKTIN_ADDR : begin
                reg_data_out [`REG_PKTIN_BITS] =  pktin_reg;
            end
            //Pktout Register
            `REG_PKTOUT_ADDR : begin
                reg_data_out [`REG_PKTOUT_BITS] =  pktout_reg;
            end
            //Pktstoredport0 Register
            `REG_PKTSTOREDPORT0_ADDR : begin
                reg_data_out [`REG_PKTSTOREDPORT0_BITS] =  pktstoredport0_reg;
            end
            //Bytesstoredport0 Register
            `REG_BYTESSTOREDPORT0_ADDR : begin
                reg_data_out [`REG_BYTESSTOREDPORT0_BITS] =  bytesstoredport0_reg;
            end
            //Pktremovedport0 Register
            `REG_PKTREMOVEDPORT0_ADDR : begin
                reg_data_out [`REG_PKTREMOVEDPORT0_BITS] =  pktremovedport0_reg;
            end
            //Bytesremovedport0 Register
            `REG_BYTESREMOVEDPORT0_ADDR : begin
                reg_data_out [`REG_BYTESREMOVEDPORT0_BITS] =  bytesremovedport0_reg;
            end
            //Pktdroppedport0 Register
            `REG_PKTDROPPEDPORT0_ADDR : begin
                reg_data_out [`REG_PKTDROPPEDPORT0_BITS] =  pktdroppedport0_reg;
            end
            //Bytesdroppedport0 Register
            `REG_BYTESDROPPEDPORT0_ADDR : begin
                reg_data_out [`REG_BYTESDROPPEDPORT0_BITS] =  bytesdroppedport0_reg;
            end
            //Pktinqueueport0 Register
            `REG_PKTINQUEUEPORT0_ADDR : begin
                reg_data_out [`REG_PKTINQUEUEPORT0_BITS] =  pktinqueueport0_reg;
            end
            //Pktstoredport1 Register
            `REG_PKTSTOREDPORT1_ADDR : begin
                reg_data_out [`REG_PKTSTOREDPORT1_BITS] =  pktstoredport1_reg;
            end
            //Bytesstoredport1 Register
            `REG_BYTESSTOREDPORT1_ADDR : begin
                reg_data_out [`REG_BYTESSTOREDPORT1_BITS] =  bytesstoredport1_reg;
            end
            //Pktremovedport1 Register
            `REG_PKTREMOVEDPORT1_ADDR : begin
                reg_data_out [`REG_PKTREMOVEDPORT1_BITS] =  pktremovedport1_reg;
            end
            //Bytesremovedport1 Register
            `REG_BYTESREMOVEDPORT1_ADDR : begin
                reg_data_out [`REG_BYTESREMOVEDPORT1_BITS] =  bytesremovedport1_reg;
            end
            //Pktdroppedport1 Register
            `REG_PKTDROPPEDPORT1_ADDR : begin
                reg_data_out [`REG_PKTDROPPEDPORT1_BITS] =  pktdroppedport1_reg;
            end
            //Bytesdroppedport1 Register
            `REG_BYTESDROPPEDPORT1_ADDR : begin
                reg_data_out [`REG_BYTESDROPPEDPORT1_BITS] =  bytesdroppedport1_reg;
            end
            //Pktinqueueport1 Register
            `REG_PKTINQUEUEPORT1_ADDR : begin
                reg_data_out [`REG_PKTINQUEUEPORT1_BITS] =  pktinqueueport1_reg;
            end
            //Pktstoredport2 Register
            `REG_PKTSTOREDPORT2_ADDR : begin
                reg_data_out [`REG_PKTSTOREDPORT2_BITS] =  pktstoredport2_reg;
            end
            //Bytesstoredport2 Register
            `REG_BYTESSTOREDPORT2_ADDR : begin
                reg_data_out [`REG_BYTESSTOREDPORT2_BITS] =  bytesstoredport2_reg;
            end
            //Pktremovedport2 Register
            `REG_PKTREMOVEDPORT2_ADDR : begin
                reg_data_out [`REG_PKTREMOVEDPORT2_BITS] =  pktremovedport2_reg;
            end
            //Bytesremovedport2 Register
            `REG_BYTESREMOVEDPORT2_ADDR : begin
                reg_data_out [`REG_BYTESREMOVEDPORT2_BITS] =  bytesremovedport2_reg;
            end
            //Pktdroppedport2 Register
            `REG_PKTDROPPEDPORT2_ADDR : begin
                reg_data_out [`REG_PKTDROPPEDPORT2_BITS] =  pktdroppedport2_reg;
            end
            //Bytesdroppedport2 Register
            `REG_BYTESDROPPEDPORT2_ADDR : begin
                reg_data_out [`REG_BYTESDROPPEDPORT2_BITS] =  bytesdroppedport2_reg;
            end
            //Pktinqueueport2 Register
            `REG_PKTINQUEUEPORT2_ADDR : begin
                reg_data_out [`REG_PKTINQUEUEPORT2_BITS] =  pktinqueueport2_reg;
            end
            //Pktstoredport3 Register
            `REG_PKTSTOREDPORT3_ADDR : begin
                reg_data_out [`REG_PKTSTOREDPORT3_BITS] =  pktstoredport3_reg;
            end
            //Bytesstoredport3 Register
            `REG_BYTESSTOREDPORT3_ADDR : begin
                reg_data_out [`REG_BYTESSTOREDPORT3_BITS] =  bytesstoredport3_reg;
            end
            //Pktremovedport3 Register
            `REG_PKTREMOVEDPORT3_ADDR : begin
                reg_data_out [`REG_PKTREMOVEDPORT3_BITS] =  pktremovedport3_reg;
            end
            //Bytesremovedport3 Register
            `REG_BYTESREMOVEDPORT3_ADDR : begin
                reg_data_out [`REG_BYTESREMOVEDPORT3_BITS] =  bytesremovedport3_reg;
            end
            //Pktdroppedport3 Register
            `REG_PKTDROPPEDPORT3_ADDR : begin
                reg_data_out [`REG_PKTDROPPEDPORT3_BITS] =  pktdroppedport3_reg;
            end
            //Bytesdroppedport3 Register
            `REG_BYTESDROPPEDPORT3_ADDR : begin
                reg_data_out [`REG_BYTESDROPPEDPORT3_BITS] =  bytesdroppedport3_reg;
            end
            //Pktinqueueport3 Register
            `REG_PKTINQUEUEPORT3_ADDR : begin
                reg_data_out [`REG_PKTINQUEUEPORT3_BITS] =  pktinqueueport3_reg;
            end
            //Pktstoredport4 Register
            `REG_PKTSTOREDPORT4_ADDR : begin
                reg_data_out [`REG_PKTSTOREDPORT4_BITS] =  pktstoredport4_reg;
            end
            //Bytesstoredport4 Register
            `REG_BYTESSTOREDPORT4_ADDR : begin
                reg_data_out [`REG_BYTESSTOREDPORT4_BITS] =  bytesstoredport4_reg;
            end
            //Pktremovedport4 Register
            `REG_PKTREMOVEDPORT4_ADDR : begin
                reg_data_out [`REG_PKTREMOVEDPORT4_BITS] =  pktremovedport4_reg;
            end
            //Bytesremovedport4 Register
            `REG_BYTESREMOVEDPORT4_ADDR : begin
                reg_data_out [`REG_BYTESREMOVEDPORT4_BITS] =  bytesremovedport4_reg;
            end
            //Pktdroppedport4 Register
            `REG_PKTDROPPEDPORT4_ADDR : begin
                reg_data_out [`REG_PKTDROPPEDPORT4_BITS] =  pktdroppedport4_reg;
            end
            //Bytesdroppedport4 Register
            `REG_BYTESDROPPEDPORT4_ADDR : begin
                reg_data_out [`REG_BYTESDROPPEDPORT4_BITS] =  bytesdroppedport4_reg;
            end
            //Pktinqueueport4 Register
            `REG_PKTINQUEUEPORT4_ADDR : begin
                reg_data_out [`REG_PKTINQUEUEPORT4_BITS] =  pktinqueueport4_reg;
            end
            //Default return value
            default: begin
                reg_data_out [31:0] =  32'hDEADBEEF;
            end
        endcase
    end

    // Read only registers, cleared on read (e.g. counters)
    always @(posedge clk)
        if (!resetn_sync) begin
            pktin_reg_clear <= #1 1'b0;
            pktin_reg_clear_d <= #1 1'b0;
            pktout_reg_clear <= #1 1'b0;
            pktout_reg_clear_d <= #1 1'b0;
            pktstoredport0_reg_clear <= #1 1'b0;
            pktstoredport0_reg_clear_d <= #1 1'b0;
            bytesstoredport0_reg_clear <= #1 1'b0;
            bytesstoredport0_reg_clear_d <= #1 1'b0;
            pktremovedport0_reg_clear <= #1 1'b0;
            pktremovedport0_reg_clear_d <= #1 1'b0;
            bytesremovedport0_reg_clear <= #1 1'b0;
            bytesremovedport0_reg_clear_d <= #1 1'b0;
            pktdroppedport0_reg_clear <= #1 1'b0;
            pktdroppedport0_reg_clear_d <= #1 1'b0;
            bytesdroppedport0_reg_clear <= #1 1'b0;
            bytesdroppedport0_reg_clear_d <= #1 1'b0;
            pktinqueueport0_reg_clear <= #1 1'b0;
            pktinqueueport0_reg_clear_d <= #1 1'b0;
            pktstoredport1_reg_clear <= #1 1'b0;
            pktstoredport1_reg_clear_d <= #1 1'b0;
            bytesstoredport1_reg_clear <= #1 1'b0;
            bytesstoredport1_reg_clear_d <= #1 1'b0;
            pktremovedport1_reg_clear <= #1 1'b0;
            pktremovedport1_reg_clear_d <= #1 1'b0;
            bytesremovedport1_reg_clear <= #1 1'b0;
            bytesremovedport1_reg_clear_d <= #1 1'b0;
            pktdroppedport1_reg_clear <= #1 1'b0;
            pktdroppedport1_reg_clear_d <= #1 1'b0;
            bytesdroppedport1_reg_clear <= #1 1'b0;
            bytesdroppedport1_reg_clear_d <= #1 1'b0;
            pktinqueueport1_reg_clear <= #1 1'b0;
            pktinqueueport1_reg_clear_d <= #1 1'b0;
            pktstoredport2_reg_clear <= #1 1'b0;
            pktstoredport2_reg_clear_d <= #1 1'b0;
            bytesstoredport2_reg_clear <= #1 1'b0;
            bytesstoredport2_reg_clear_d <= #1 1'b0;
            pktremovedport2_reg_clear <= #1 1'b0;
            pktremovedport2_reg_clear_d <= #1 1'b0;
            bytesremovedport2_reg_clear <= #1 1'b0;
            bytesremovedport2_reg_clear_d <= #1 1'b0;
            pktdroppedport2_reg_clear <= #1 1'b0;
            pktdroppedport2_reg_clear_d <= #1 1'b0;
            bytesdroppedport2_reg_clear <= #1 1'b0;
            bytesdroppedport2_reg_clear_d <= #1 1'b0;
            pktinqueueport2_reg_clear <= #1 1'b0;
            pktinqueueport2_reg_clear_d <= #1 1'b0;
            pktstoredport3_reg_clear <= #1 1'b0;
            pktstoredport3_reg_clear_d <= #1 1'b0;
            bytesstoredport3_reg_clear <= #1 1'b0;
            bytesstoredport3_reg_clear_d <= #1 1'b0;
            pktremovedport3_reg_clear <= #1 1'b0;
            pktremovedport3_reg_clear_d <= #1 1'b0;
            bytesremovedport3_reg_clear <= #1 1'b0;
            bytesremovedport3_reg_clear_d <= #1 1'b0;
            pktdroppedport3_reg_clear <= #1 1'b0;
            pktdroppedport3_reg_clear_d <= #1 1'b0;
            bytesdroppedport3_reg_clear <= #1 1'b0;
            bytesdroppedport3_reg_clear_d <= #1 1'b0;
            pktinqueueport3_reg_clear <= #1 1'b0;
            pktinqueueport3_reg_clear_d <= #1 1'b0;
            pktstoredport4_reg_clear <= #1 1'b0;
            pktstoredport4_reg_clear_d <= #1 1'b0;
            bytesstoredport4_reg_clear <= #1 1'b0;
            bytesstoredport4_reg_clear_d <= #1 1'b0;
            pktremovedport4_reg_clear <= #1 1'b0;
            pktremovedport4_reg_clear_d <= #1 1'b0;
            bytesremovedport4_reg_clear <= #1 1'b0;
            bytesremovedport4_reg_clear_d <= #1 1'b0;
            pktdroppedport4_reg_clear <= #1 1'b0;
            pktdroppedport4_reg_clear_d <= #1 1'b0;
            bytesdroppedport4_reg_clear <= #1 1'b0;
            bytesdroppedport4_reg_clear_d <= #1 1'b0;
            pktinqueueport4_reg_clear <= #1 1'b0;
            pktinqueueport4_reg_clear_d <= #1 1'b0;
        end
        else begin
            pktin_reg_clear <= #1 pktin_reg_clear_d;
            pktin_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTIN_ADDR)) ? 1'b1 : 1'b0;
            pktout_reg_clear <= #1 pktout_reg_clear_d;
            pktout_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTOUT_ADDR)) ? 1'b1 : 1'b0;
            pktstoredport0_reg_clear <= #1 pktstoredport0_reg_clear_d;
            pktstoredport0_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTSTOREDPORT0_ADDR)) ? 1'b1 : 1'b0;
            bytesstoredport0_reg_clear <= #1 bytesstoredport0_reg_clear_d;
            bytesstoredport0_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESSTOREDPORT0_ADDR)) ? 1'b1 : 1'b0;
            pktremovedport0_reg_clear <= #1 pktremovedport0_reg_clear_d;
            pktremovedport0_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTREMOVEDPORT0_ADDR)) ? 1'b1 : 1'b0;
            bytesremovedport0_reg_clear <= #1 bytesremovedport0_reg_clear_d;
            bytesremovedport0_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESREMOVEDPORT0_ADDR)) ? 1'b1 : 1'b0;
            pktdroppedport0_reg_clear <= #1 pktdroppedport0_reg_clear_d;
            pktdroppedport0_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTDROPPEDPORT0_ADDR)) ? 1'b1 : 1'b0;
            bytesdroppedport0_reg_clear <= #1 bytesdroppedport0_reg_clear_d;
            bytesdroppedport0_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESDROPPEDPORT0_ADDR)) ? 1'b1 : 1'b0;
            pktinqueueport0_reg_clear <= #1 pktinqueueport0_reg_clear_d;
            pktinqueueport0_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTINQUEUEPORT0_ADDR)) ? 1'b1 : 1'b0;
            pktstoredport1_reg_clear <= #1 pktstoredport1_reg_clear_d;
            pktstoredport1_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTSTOREDPORT1_ADDR)) ? 1'b1 : 1'b0;
            bytesstoredport1_reg_clear <= #1 bytesstoredport1_reg_clear_d;
            bytesstoredport1_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESSTOREDPORT1_ADDR)) ? 1'b1 : 1'b0;
            pktremovedport1_reg_clear <= #1 pktremovedport1_reg_clear_d;
            pktremovedport1_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTREMOVEDPORT1_ADDR)) ? 1'b1 : 1'b0;
            bytesremovedport1_reg_clear <= #1 bytesremovedport1_reg_clear_d;
            bytesremovedport1_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESREMOVEDPORT1_ADDR)) ? 1'b1 : 1'b0;
            pktdroppedport1_reg_clear <= #1 pktdroppedport1_reg_clear_d;
            pktdroppedport1_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTDROPPEDPORT1_ADDR)) ? 1'b1 : 1'b0;
            bytesdroppedport1_reg_clear <= #1 bytesdroppedport1_reg_clear_d;
            bytesdroppedport1_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESDROPPEDPORT1_ADDR)) ? 1'b1 : 1'b0;
            pktinqueueport1_reg_clear <= #1 pktinqueueport1_reg_clear_d;
            pktinqueueport1_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTINQUEUEPORT1_ADDR)) ? 1'b1 : 1'b0;
            pktstoredport2_reg_clear <= #1 pktstoredport2_reg_clear_d;
            pktstoredport2_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTSTOREDPORT2_ADDR)) ? 1'b1 : 1'b0;
            bytesstoredport2_reg_clear <= #1 bytesstoredport2_reg_clear_d;
            bytesstoredport2_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESSTOREDPORT2_ADDR)) ? 1'b1 : 1'b0;
            pktremovedport2_reg_clear <= #1 pktremovedport2_reg_clear_d;
            pktremovedport2_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTREMOVEDPORT2_ADDR)) ? 1'b1 : 1'b0;
            bytesremovedport2_reg_clear <= #1 bytesremovedport2_reg_clear_d;
            bytesremovedport2_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESREMOVEDPORT2_ADDR)) ? 1'b1 : 1'b0;
            pktdroppedport2_reg_clear <= #1 pktdroppedport2_reg_clear_d;
            pktdroppedport2_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTDROPPEDPORT2_ADDR)) ? 1'b1 : 1'b0;
            bytesdroppedport2_reg_clear <= #1 bytesdroppedport2_reg_clear_d;
            bytesdroppedport2_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESDROPPEDPORT2_ADDR)) ? 1'b1 : 1'b0;
            pktinqueueport2_reg_clear <= #1 pktinqueueport2_reg_clear_d;
            pktinqueueport2_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTINQUEUEPORT2_ADDR)) ? 1'b1 : 1'b0;
            pktstoredport3_reg_clear <= #1 pktstoredport3_reg_clear_d;
            pktstoredport3_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTSTOREDPORT3_ADDR)) ? 1'b1 : 1'b0;
            bytesstoredport3_reg_clear <= #1 bytesstoredport3_reg_clear_d;
            bytesstoredport3_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESSTOREDPORT3_ADDR)) ? 1'b1 : 1'b0;
            pktremovedport3_reg_clear <= #1 pktremovedport3_reg_clear_d;
            pktremovedport3_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTREMOVEDPORT3_ADDR)) ? 1'b1 : 1'b0;
            bytesremovedport3_reg_clear <= #1 bytesremovedport3_reg_clear_d;
            bytesremovedport3_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESREMOVEDPORT3_ADDR)) ? 1'b1 : 1'b0;
            pktdroppedport3_reg_clear <= #1 pktdroppedport3_reg_clear_d;
            pktdroppedport3_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTDROPPEDPORT3_ADDR)) ? 1'b1 : 1'b0;
            bytesdroppedport3_reg_clear <= #1 bytesdroppedport3_reg_clear_d;
            bytesdroppedport3_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESDROPPEDPORT3_ADDR)) ? 1'b1 : 1'b0;
            pktinqueueport3_reg_clear <= #1 pktinqueueport3_reg_clear_d;
            pktinqueueport3_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTINQUEUEPORT3_ADDR)) ? 1'b1 : 1'b0;
            pktstoredport4_reg_clear <= #1 pktstoredport4_reg_clear_d;
            pktstoredport4_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTSTOREDPORT4_ADDR)) ? 1'b1 : 1'b0;
            bytesstoredport4_reg_clear <= #1 bytesstoredport4_reg_clear_d;
            bytesstoredport4_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESSTOREDPORT4_ADDR)) ? 1'b1 : 1'b0;
            pktremovedport4_reg_clear <= #1 pktremovedport4_reg_clear_d;
            pktremovedport4_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTREMOVEDPORT4_ADDR)) ? 1'b1 : 1'b0;
            bytesremovedport4_reg_clear <= #1 bytesremovedport4_reg_clear_d;
            bytesremovedport4_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESREMOVEDPORT4_ADDR)) ? 1'b1 : 1'b0;
            pktdroppedport4_reg_clear <= #1 pktdroppedport4_reg_clear_d;
            pktdroppedport4_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTDROPPEDPORT4_ADDR)) ? 1'b1 : 1'b0;
            bytesdroppedport4_reg_clear <= #1 bytesdroppedport4_reg_clear_d;
            bytesdroppedport4_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_BYTESDROPPEDPORT4_ADDR)) ? 1'b1 : 1'b0;
            pktinqueueport4_reg_clear <= #1 pktinqueueport4_reg_clear_d;
            pktinqueueport4_reg_clear_d <= #1(reg_rden && (axi_araddr==`REG_PKTINQUEUEPORT4_ADDR)) ? 1'b1 : 1'b0;
        end

    // Output register or memory read data
    always @( posedge S_AXI_ACLK )
        if ( S_AXI_ARESETN == 1'b0 )
            axi_rdata <= 0;
        else
            // When there is a valid read address (S_AXI_ARVALID) with
            // acceptance of read address by the slave (axi_arready),
            // output the read dada
            if (reg_rden)
                axi_rdata <= reg_data_out;  // register read data
endmodule
