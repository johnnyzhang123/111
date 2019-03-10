//todo k0k1  g constant
module bitcoin_hash (input logic clk, reset_n, start,
 input logic [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);
 // SHA256 K constants
 parameter int sha256_k[0:63] = '{
 32'h428a2f98,32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
 32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
 32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
 32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
 32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
 32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
 32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
 32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};
logic [5:0] nonces[16];
logic [31:0] w[16][16],H0[16],H1[16],H2[16],H3[16],H4[16],H5[16],H6[16],H7[16],FC0[16],FC1[16],FC2[16],FC3[16],FC4[16],FC5[16],FC6[16],FC7[16];
logic [31:0] a[16],b[16],c[16],d[16],e[16],f[16],g[16],h[16],sum[16];
logic [31:0] inter;
logic [6:0] count;
logic [4:0]n;
enum logic [3:0] {IDLE,READ1,READ2,PPCOMPUTE,PREP,PREP2,PREP3,PREP4,COMPUTE,REST,COMPUTE2,WRITE,REST2,BACK,DONE} state;
assign mem_clk=clk;
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g,s);
logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
 ch = (e & f) ^ ((~e) & g);
 t1=S1+ch+s;
 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
 maj = (a & b) ^ (a & c) ^ (b & c);
 t2 = maj + S0;
 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction
function logic [31:0] rightrotate(input logic [31:0] x,
 input logic [7:0] r);
 rightrotate = (x >> r) | (x << (32-r));
endfunction
function logic [31:0] wtnew(input logic [4:0] t); // function with no inputs
 logic [31:0] s0, s1;
 s0 = rightrotate(w[t][1],7)^rightrotate(w[t][1],18)^(w[t][1]>>3);
 s1 = rightrotate(w[t][14],17)^rightrotate(w[t][14],19)^(w[t][14]>>10);
 wtnew = w[t][0] + s0 + w[t][9] + s1;
endfunction
always_ff @(posedge clk, negedge reset_n) begin
	$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, count: %d,mem_read_data: %h, mem_addr:%h, sum:%h ",state,a[0],b[0],c[0],d[0],e[0],f[0],g[0],h[0],w[0][15],count-1,mem_read_data,mem_addr,sum[0]);
	if (!reset_n) begin
		state <= IDLE;
		done<=0;
		count<=0;
	end 
	else case(state)
	
	IDLE:begin
		if(start) begin
			mem_we <= 0;
		   mem_addr <= message_addr;
			for(int t=0;t<16;t++)begin
				H0[t]<=32'h6a09e667;
				H1[t]<=32'hbb67ae85;
				H2[t]<=32'h3c6ef372;
				H3[t]<=32'ha54ff53a;
				H4[t]<=32'h510e527f;
				H5[t]<=32'h9b05688c;
				H6[t]<=32'h1f83d9ab;
				H7[t]<=32'h5be0cd19; 
				g[t]<=32'h5be0cd19;
				nonces[t]<=t;
			end
			state <= READ1;
		end
	end
			 
	READ1: begin
		state <= READ2;				
		mem_addr <= mem_addr + 1;	
	end
			
	READ2: begin
		for(int t=0;t<16;t++)begin
			w[t][15] <= mem_read_data;
		end
		count <= 0;
		state <= PPCOMPUTE;
		mem_addr <= mem_addr + 1;
	end
	PPCOMPUTE: begin
		for(int t=0;t<16;t++)begin
			sum[t] <= w[t][15] + sha256_k[count] + g[t];
			a[t]<= H0[t];
			b[t]<= H1[t];
			c[t]<= H2[t];
			d[t]<= H3[t];
			e[t]<= H4[t];
			f[t]<= H5[t];
			g[t]<= H6[t];
			h[t]<= H7[t];
			for (int n = 0; n < 15; n++)begin 
				w[t][n] <= w[t][n+1];
			end
			w[t][15] <= mem_read_data;
		end
		 count<=count+1;
		 mem_addr <= mem_addr + 1;
		 state <= PREP;
	end	 
	PREP: begin
		for(int t=0;t<16;t++)begin
			for(n=0;n<15;n++)begin
				w[t][n]<=w[t][n+1];
			end 
			{a[t], b[t], c[t], d[t], e[t], f[t], g[t], h[t]} <= sha256_op(a[t], b[t], c[t], d[t], e[t], f[t], g[t],sum[t]);
			sum[t]<=w[t][15]+sha256_k[count]+g[t];
		end
		if(count<15)begin
			for(int t=0;t<16;t++)begin
				w[t][15]<=mem_read_data;
			end
		end
		else begin
			for(int t=0;t<16;t++)begin
				w[t][15]<=wtnew(t);
			end
			state<=PREP2;
			inter<=mem_read_data;
		end
		count<=count+1;
		mem_addr<=mem_addr+1;		
	end
	PREP2: begin//first block 16-63
		for(int t=0;t<16;t++)begin
			for(n=0;n<15;n++)begin
				w[t][n]<=w[t][n+1];
			end 
			w[t][15]<=wtnew(t);
			sum[t]<=w[t][15]+sha256_k[count]+g[t];
			{a[t], b[t], c[t], d[t], e[t], f[t], g[t], h[t]} <= sha256_op(a[t], b[t], c[t], d[t], e[t], f[t], g[t], sum[t]);//needs to be changed, figure out what needs to be precomputed
					mem_addr<=16;

		end
		if(count==64)begin
			for(int t=0;t<16;t++)begin
				w[t][15]<=inter;
			end
			mem_addr<=mem_addr+1;
			state<=PREP3;
		end
		count<=count+1;
	end
	PREP3:begin
		for(int t=0;t<16;t++)begin
			w[t][15]<=mem_read_data;
			for(n=0;n<15;n++)begin
				w[t][n]<=w[t][n+1];
			end
			FC0[t]<=H0[t]+a[t];
			FC1[t]<=H1[t]+b[t];
			FC2[t]<=H2[t]+c[t];
			FC3[t]<=H3[t]+d[t];
			FC4[t]<=H4[t]+e[t];
			FC5[t]<=H5[t]+f[t];
			FC6[t]<=H6[t]+g[t];
			FC7[t]<=H7[t]+h[t];
			H0[t]<=H0[t]+a[t];
			H1[t]<=H1[t]+b[t];
			H2[t]<=H2[t]+c[t];						
			H3[t]<=H3[t]+d[t];
			H4[t]<=H4[t]+e[t];
			H5[t]<=H5[t]+f[t];
			H6[t]<=H6[t]+g[t];
			H7[t]<=H7[t]+h[t];
			g[t]<=H7[t]+h[t];
		end
		count<=0;
		state<=PREP4;
		mem_addr<=mem_addr+1;
	end
	PREP4:begin
		for(int t=0;t<16;t++)begin
			w[t][15]<=mem_read_data;
			for(n=0;n<15;n++)begin
				w[t][n]<=w[t][n+1];
			end
			a[t]<=H0[t];
			b[t]<=H1[t];
			c[t]<=H2[t];						
			d[t]<=H3[t];
			e[t]<=H4[t];
			f[t]<=H5[t];
			g[t]<=H6[t];
			h[t]<=H7[t];
			sum[t]<=w[t][15]+sha256_k[count]+g[t];
		end
		mem_addr<=mem_addr+1;
		count<=count+1;
		state<=COMPUTE;
	end
	COMPUTE: begin
		if(count<65) begin
			for(int t=0;t<16;t++)begin
				sum[t]<=w[t][15]+sha256_k[count]+g[t];
				{a[t], b[t], c[t], d[t], e[t], f[t], g[t], h[t]} <= sha256_op(a[t], b[t], c[t], d[t], e[t], f[t], g[t], sum[t]);
				for(n=0;n<15;n++)begin
					w[t][n]<=w[t][n+1];
				end
			end
				if(count==1)begin
					for(int t=0;t<16;t++)begin
						w[t][15]<=mem_read_data;
					end
					mem_addr<=mem_addr+1;
				end
				else if(count==2) begin
					for(int t=0;t<16;t++)begin
						w[t][15]<=nonces[t];
					end
				end
				else if(count==3)begin
					for(int t=0;t<16;t++)begin
						w[t][15]<=32'h80000000;
					end
				end
				else if(count>3 & count<14) begin
					for(int t=0;t<16;t++)begin
						w[t][15]<=32'h00000000;
					end
				end
				else if(count==14)begin
					for(int t=0;t<16;t++)begin
						w[t][15]<=32'd640;
					end
				end
				else if(count>14 & count<64)begin
					for(int t=0;t<16;t++)begin
						w[t][15]<=wtnew(t);			
					end
				end
			count<=count+1;
		end
			else begin
				for(int t=0;t<16;t++)begin
					w[t][15]<=H0[t]+a[t];
					w[t][0]<=H1[t]+b[t];//cc=1
					w[t][1]<=H2[t]+c[t];//cc=2
					w[t][2]<=H3[t]+d[t];
					w[t][3]<=H4[t]+e[t];
					w[t][4]<=H5[t]+f[t];
					w[t][5]<=H6[t]+g[t];
					w[t][6]<=H7[t]+h[t];
					w[t][7]<=32'h80000000;
					w[t][8]<=32'h00000000;
					w[t][9]<=32'h00000000;
					w[t][10]<=32'h00000000;
					w[t][11]<=32'h00000000;
					w[t][12]<=32'h00000000;
					w[t][13]<=32'h00000000;
					w[t][14]<='d256;
					H0[t]<= 'h6a09e667;
					H1[t]<= 'hbb67ae85;
					H2[t]<= 'h3c6ef372;
					H3[t]<= 'ha54ff53a;
					H4[t]<= 'h510e527f;
					H5[t]<= 'h9b05688c;
					H6[t]<= 'h1f83d9ab;
					H7[t]<= 'h5be0cd19;
					g[t]<='h5be0cd19;
				end
				count<=0;
				state<=REST;
			end
		end//last round load 
	REST: begin
		for(int t=0;t<16;t++)begin
			a[t]<=H0[t];
			b[t]<=H1[t];
			c[t]<=H2[t];		
			d[t]<=H3[t];
			e[t]<=H4[t];
			f[t]<=H5[t];
			g[t]<=H6[t];
			h[t]<=H7[t];
			sum[t]<=w[t][15]+sha256_k[count]+g[t];
		//w[15]<=inter[count];
			w[t][15]<=w[t][0];
			for (int n = 0; n < 15; n++) begin
				w[t][n] <= w[t][n+1];
			end
		end
		count<=count+1;
		mem_addr<=17;	
		state<=COMPUTE2;
	end
	COMPUTE2: begin
			for(int t=0;t<16;t++)begin
				for (int n = 0; n < 15; n++) begin
					w[t][n] <= w[t][n+1];
				end
				{a[t], b[t], c[t], d[t], e[t], f[t], g[t], h[t]} <= sha256_op(a[t], b[t], c[t], d[t], e[t], f[t], g[t],sum[t]);
				sum[t]<=w[t][15]+sha256_k[count]+g[t];
			end
		count<=count+1;
			if(count<15)begin
				for(int t=0;t<16;t++)begin
					w[t][15]<=w[t][0];
				end
			end
			/*if(count<7)begin	
				w[15]<=inter[count];
			end
			else if(count==7)begin
				w[15]<=32'h80000000;
			end
			else if(count>7 & count<14) begin
				w[15]<=32'h00000000;
			end
			else if(count==14)begin
				w[15]<='d256;
			end*/
			else begin
				for(int t=0;t<16;t++)begin
					w[t][15]<=wtnew(t);			
				end
				if(count==64)begin
					for(int t=0;t<16;t++)begin
						w[t][15]<=inter;
						g[t]<=FC7[t];
						H0[t]<=FC0[t];
						H1[t]<=FC1[t];
						H2[t]<=FC2[t];						
						H3[t]<=FC3[t];
						H4[t]<=FC4[t];
						H5[t]<=FC5[t];
						H6[t]<=FC6[t];
						H7[t]<=FC7[t];
					end
					count<=0;
					//t<=0;
					state<=WRITE;
				end
			end
	end
	WRITE:begin
		mem_we<=1;
		if(count!='d16)begin
			mem_addr<=output_addr+nonces[count];
			mem_write_data<=a[count]+32'h6a09e667;
			count<=count+1;
		end
		else begin
			state<=DONE;
		end
	end
	/*BACK: begin
	if(nonces!='h0000000F)begin
		mem_we<=0;
		mem_addr<=18;
		nonces<=nonces+1;
		state<=PREP4;
	end
	else begin
		state<=DONE;
	end
	end*/
	DONE:begin
		done<=1;
		state<=IDLE;
	end
	endcase
end
endmodule
