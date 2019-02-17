module bitcoin_hash (input logic clk, reset_n, start,
 input logic [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);
 // SHA256 K constants
 parameter int sha256_k[0:63] = '{
 32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
 32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
 32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
 32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
 32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
 32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
 32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
 32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};
parameter NUM_NONCES = 16;
logic [31:0] w[16],H0,H1,H2,H3,H4,H5,H6,H7,FC0,FC1,FC2,FC3,FC4,FC5,FC6,FC7;
logic [31:0] a,b,c,d,e,f,g,h;
logic [8:0] write_count,read_count,calc_count,nonces;
logic [4:0]n;
logic[2:0]block;
enum logic [2:0] {IDLE=3'b000,READ=3'b001,PRECOMPUTE=3'b010,COMPUTE=3'b011,WRITE=3'b100, DONE=3'b101} state;
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
assign mem_clk=clk;
always_ff @(posedge clk, negedge reset_n) begin
	if (!reset_n) begin
		state <= IDLE;
		done<=0;
		calc_count<=0;
		read_count<=0;
		write_count<=0;
		block<=0;
		H0<= 'h6a09e667;
		H1<= 'hbb67ae85;
		H2<= 'h3c6ef372;
		H3<= 'ha54ff53a;
		H4<= 'h510e527f;
		H5<= 'h9b05688c;
		H6<= 'h1f83d9ab;
		H7<= 'h5be0cd19;
		nonces<='h00000000;
	end 
	else case(state)
	IDLE: begin
		state<=READ;
		mem_we<=0; 
		mem_addr<= message_addr;
	end
	READ: begin
		a<=H0;
		b<=H1;
		c<=H2;
		d<=H3;
		e<=H4;
		f<=H5;
		g<=H6;
		h<=H7;
		mem_we<=0;
		mem_addr<=message_addr+1;
		state<=PRECOMPUTE;
	end
	PRECOMPUTE: begin
		if(read_count<16)begin
			w[15]<=mem_read_data;
			{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, mem_read_data, sha256_k[calc_count]);
			$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h,mem_read_data: %h, mem_addr:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count,mem_read_data,mem_addr);
			calc_count<=calc_count+1;
			for(n=14;n>-1;n--)begin
				w[n]<=w[n+1];
			end
			mem_we<=0;
			mem_addr<=message_addr+read_count+2;
			read_count<=read_count+1;
			state<=PRECOMPUTE;
		end
		else begin//first block 16-64
			w[15]<=wtnew;
			for (int n = 0; n < 15; n++) begin
				w[n] <= w[n+1];
			end
			{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, wtnew, sha256_k[calc_count]);//needs to be changed, figure out what needs to be precomputed
			$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count);			
			calc_count<=calc_count+1;
			state<=PRECOMPUTE;
			if(calc_count>62)begin
				mem_we<=0;
				mem_addr<=message_addr+read_count;
				read_count<=read_count+1;
				if(calc_count==64)begin
					FC0<=H0+a;
					FC1<=H1+b;
					FC2<=H2+c;
					FC3<=H3+d;
					FC4<=H4+e;
					FC5<=H5+f;
					FC6<=H6+g;
					FC7<=H7+h;
					H0<=H0+a;
					H1<=H1+b;
					H2<=H2+c;						
					H3<=H3+d;
					H4<=H4+e;
					H5<=H5+f;
					H6<=H6+g;
					H7<=H7+h;
					block<=1;
					calc_count<=0;
					state<=COMPUTE;
				end
			end
		end	
	end
	COMPUTE: begin
		if(block==1)begin
			if(calc_count<3)begin
				w[15]<=mem_read_data;
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, mem_read_data, sha256_k[calc_count]);
							$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count);			
				calc_count<=calc_count+1;
				for(n=14;n>-1;n--)begin
					w[n]<=w[n+1];
				end
				mem_we<=0;
				mem_addr<=message_addr+read_count;
				read_count<=read_count+1;
				state<=COMPUTE; 
			end
			else if(calc_count==3)begin
				w[15]<=nonces;
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, nonces, sha256_k[calc_count]);
							$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count);			

				for(n=14;n>-1;n--)begin
					w[n]<=w[n+1];
				end
				read_count<=read_count+1;
				calc_count<=calc_count+1;
				nonces<=nonces+1;				
				state<=COMPUTE;
			end
			else if(calc_count==4)begin
				w[15]<=32'h80000000;
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, 32'h80000000, sha256_k[calc_count]);
							$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count);			

				for(n=14;n>-1;n--)begin
					w[n]<=w[n+1];
				end				
				calc_count<=calc_count+1;
				read_count<=read_count+1;
				state<=COMPUTE;
			end
			else if(calc_count==15)begin
					w[15]<=32'd640;
					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, 32'd640, sha256_k[calc_count]);
						$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count);			
		
					calc_count<=calc_count+1;
					state<=COMPUTE;
			end
			else if(calc_count>15 & calc_count<64)begin
				w[15]<=wtnew;
				for (int n = 0; n < 15; n++) begin
					w[n] <= w[n+1];
				end
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, wtnew, sha256_k[calc_count]);
							$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count);			

				calc_count<=calc_count+1;
			end
			else if(calc_count==64)begin
				H0<= 'h6a09e667;
				H1<= 'hbb67ae85;
				H2<= 'h3c6ef372;
				H3<= 'ha54ff53a;
				H4<= 'h510e527f;
				H5<= 'h9b05688c;
				H6<= 'h1f83d9ab;
				H7<= 'h5be0cd19;
				w[0]<=H0+a;
				w[1]<=H1+b;
				w[2]<=H2+c;
				w[3]<=H3+d;
				w[4]<=H4+e;
				w[5]<=H5+f;
				w[6]<=H6+g;
				w[7]<=H7+h;
				w[8]=32'h80000000;
				w[9]='h00000000;
				w[10]='h00000000;
				w[11]='h00000000;
				w[12]='h00000000;
				w[13]='h00000000;
				w[14]='h00000000;
				w[15]='d256;
				calc_count<=0;
			end
			else begin
				w[15]=32'h00000000;
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, 32'h00000000, sha256_k[calc_count]);
							$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count);			

				for(n=14;n>-1;n--)begin
					w[n]<=w[n+1];
				end
			end
			state<=COMPUTE;
		end//last round load 
		else if(block==2)begin
			if(calc_count<16)begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[calc_count], sha256_k[calc_count]);
							$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count);			

				calc_count<=calc_count+1;
				state<=COMPUTE;
			end
			else if(calc_count>15 & calc_count<64)begin
				w[15]<=wtnew;
				for (int n = 0; n < 15; n++) begin
					w[n] <= w[n+1];
				end				
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, wtnew, sha256_k[calc_count]);
							$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, t: %d, i:%h",state,a,b,c,d,e,f,g,h,w[calc_count-1],calc_count-1,read_count);			

				calc_count<=calc_count+1;
				state<=COMPUTE;
			end
			else begin
				state<=WRITE;
				block<=1;
				calc_count<=0;
				read_count<=16;
				H0<=FC0;
				H1<=FC1;
				H2<=FC2;						
				H3<=FC3;
				H4<=FC4;
				H5<=FC5;
				H6<=FC6;
				H7<=FC7;
			end
		end
	end
	
	WRITE: begin
		mem_we<=1;
		mem_addr <= output_addr+write_count;
		write_count<=write_count+1;
		mem_write_data<=H0+a;
		state<=COMPUTE;
		if(nonces=='h0000000F)begin
			state<=DONE;
		end
	end
	DONE:begin
		done<=1;
		state<=IDLE;
	end
	endcase
	end
always_ff @(posedge clk, negedge reset_n)begin
	$display("time:%h",calc_count);
end
endmodule