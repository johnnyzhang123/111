module simplified_sha256(input logic clk, reset_n, start,
 input logic [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);
 
 // SHA256 K constants
 parameter int sha256_k[0:63] = {
 32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
 32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
 32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
 32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
 32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
 32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
 32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
 32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};


assign mem_clk=clk;
logic [31:0] w[16];
enum logic [2:0] {IDLE=2'b000,READ=2'b001,SCOMPUTE=2'b010,LCOMPUTE=2'b011,WRITE=2'b100, DONE=2'b101} state;
 
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w, k);
 logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
 ch = (e & f) ^ ((~e) & g);
 t1 = ch + S1 + h + k + w;
 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
 maj = (a & b) ^ (a & c) ^ (b & c);
 t2 = maj + S0;
 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// right rotation
function logic [31:0] rightrotate(input logic [31:0] x,
 input logic [7:0] r);
 rightrotate = (x >> r) | (x << (32-r));
endfunction

function logic [31:0] wtnew; // function with no inputs
 logic [31:0] s0, s1,os0;
 os0=s0;
 s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
 s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
 wtnew = w[0] + s0 + w[9] + s1;
endfunction

always_ff @(posedge clk, negedge reset_n) begin
	if (!reset_n) begin
		state <= IDLE;
		done<=0;
		count<=0;
	end 
 else case(state)
	IDLE: begin
		if(start) begin
			H0<= 'h6a09e667;
			H1<= 'hbb67ae85;
			H2<= 'h3c6ef372;
			H3<= 'ha54ff53a;
			H4<= 'h510e527f;
			H5<= 'h9b05688c;
			H6<= 'h1f83d9ab;
			H7<= 'h5be0cd19;
			i<=1;
			count<=0;
			block<=0;
			state<=READ;
			mem_we<=0; 
			mem_addr<= message_addr;
			end
	end
 
	READ:begin
		if(i<16 & count<16)begin//for block1 0<count<16 stage
			if(i==1)begin
				a<=H0;
				b<=H1;
				c<=H2;
				d<=H3;
				e<=H4;
				f<=H5;
				g<=H6;
				h<=H7;
			end
			mem_we<=0;
			mem_addr<= message_addr+i;
			i<=i+1;
			if(i/2==0)begin //determine if i is even, if so read again if not go to sc
				state<=READ;
			end
		else begin
			state<=SCOMPUTE;
		end
		end
	
 //right up to here
 
		else if(i>15 & i<20)begin
			if(i==16)begin
				a<=H0+a;
				b<=H1+b;
				c<=H2+c;
				d<=H3+d;
				e<=H4+e;
				f<=H5+f;
				g<=H6+g;
				h<=H7+h;
			end
			mem_we<=0;
			mem_addr<= message_addr+i;
			i<=i+1;
			if(i/2==0)begin //determine if i is even, if so read again if not go to sc
					state<=READ;
			end
			else begin
					state<=SCOMPUTE;
			end
		end
		else if(i>19 & i<32)begin//beginning of a new bloc
	end
		
			if(i==20)begin
				w[i-16]=32'h80000000;
				i<=i+1;
				state<=READ;
			end			
			else if(i>20 & i<31)begin
				w[i-16]=32'h00000000; 
				i<=i+1;
				if(i/2==0)begin //determine if i is even, if so read again if not go to sc
					state<=READ;
				end
				else begin
					state<=SCOMPUTE;
				end
			end
			else if(i==31)begin
				w[15] <= 32'd640;
				state<=SCOMPUTE;
			end
		end
 
	SCOMPUTE: begin
		w[count]<=mem_read_data;//for lcomp
		{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, mem_read_data, k[count]);
		count<=count+1;
		if(count/2==0 & count<16)begin
			state<=SCOMPUTE;
		end
		else if(count==15) begin
			for (int n = 0; n < 15; n++) w[n] <= w[n+1]; // just wires
			w[15]<=wtnew;
			state<=LCOMPUTE;//stop it from going back to read
 //declare wtnew because it takes one cycle
		end
		else if(count/2==1 & count<16) begin
			state<=READ;
		end
 //every time i is even sc again, i is odd go back to read
	end

 
	LCOMPUTE: begin
	if(count!=63)begin
		{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[count], k[count]);
		for (int n = 0; n < 15; n++) w[n] <= w[n+1];
		w[15]<=wtnew;
		count<=count+1;
		state<=LCOMPUTE;
	end
	else begin
		block<=1;
		count<=0;
		state<=write;
	end
 end
 
	WRITE: begin
	if(block==1)begin
		mem_we<=1;
		mem_addr <= output_addr;
		mem_write_data <= H0;
		mem_addr <= output_addr+1;
		mem_write_data <= H1;
		mem_addr <= output_addr+2;
		mem_write_data <= H2;
		mem_addr <= output_addr+3;
		mem_write_data <= H3;
		mem_addr <= output_addr+4;
		mem_write_data <= H4;
		mem_addr <= output_addr+5;
		mem_write_data <= H5;
		mem_addr <= output_addr+6;
		mem_write_data <= H6;
		mem_addr <= output_addr+7;
		mem_write_data <= H7;
		state<=DONE;
	end
 end
 
	DONE:begin
		done<=1;
		state<=IDLE;
	end
 endcase
end


endmodule