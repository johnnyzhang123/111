//fmax 104.17 area 4036 2166
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
logic [31:0] w[16],p3[16],H0,H1,H2,H3,H4,H5,H6,H7,FC0,FC1,FC2,FC3,FC4,FC5,FC6,FC7;
logic [31:0] a,b,c,d,e,f,g,h,sum;
logic [31:0] Ma,Mb,Mc,Md,Me,Mf,Mg,Mh;
logic [8:0] calc_count,nonces;
logic [4:0]n;
logic[2:0]block;
enum logic [3:0] {IDLE=4'b0000,READ1=4'b0001,READ2=4'b0010,PPCOMPUTE=4'b0011,PRECOMPUTE=4'b0100,MIDDLE=4'b0101,COMPUTE=4'b0110,COMPUTE2=4'b0111, WRITE=4'b1000,DONE=4'b1001} state;
assign mem_clk=clk;
//function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w, k);
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g,s);
logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
 ch = (e & f) ^ ((~e) & g);
 //t1 = ch + S1 + h + k + w;
 t1=S1+ch+s;
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
 logic [31:0] s0, s1;
 s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
 s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
 wtnew = w[0] + s0 + w[9] + s1;
endfunction
always_ff @(posedge clk, negedge reset_n) begin
	$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, calc_count: %d,mem_read_data: %h, mem_addr:%h, sum:%h ",state,a,b,c,d,e,f,g,h,w[15],calc_count-1,mem_read_data,mem_addr,sum);
	if (!reset_n) begin
		state <= IDLE;
		done<=0;
		calc_count<=0;
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
	
	IDLE:
		if(start) begin
			mem_we <= 0;
		   mem_addr <= message_addr;
			H0<=32'h6a09e667;
         H1<=32'hbb67ae85;
         H2<=32'h3c6ef372;
         H3<=32'ha54ff53a;
         H4<=32'h510e527f;
         H5<=32'h9b05688c;
         H6<=32'h1f83d9ab;
         H7<=32'h5be0cd19; 
			calc_count <= 0;
			state <= READ1;
	end
			 
	READ1: begin
		state <= READ2;				
		mem_addr <= mem_addr + 1;	
	end
			
	READ2: begin
		state <= PPCOMPUTE;
		w[15] <= mem_read_data;
		mem_addr <= mem_addr + 1;
		a<= H0;
		b<= H1;
		c<= H2;
		d<= H3;
		e<= H4;
		f<= H5;
		g<= H6;
		h<= H7;
	end
		
	PPCOMPUTE: begin
	    sum <= w[15] + sha256_k[calc_count] + h;
		 for (int n = 0; n < 15; n++)begin 
			w[n] <= w[n+1];
		 end
		 w[15] <= mem_read_data;
		 mem_addr <= mem_addr + 1;
		 state <= PRECOMPUTE;
		 //calc_count <= calc_count + 1;
	end	 
	PRECOMPUTE: begin
		for(n=0;n<15;n++)begin
			w[n]<=w[n+1];
		end
		if(calc_count<16)begin
			if(calc_count<14)begin
				w[15]<=mem_read_data;
			end
			else begin
				w[15]<=wtnew;
			end
			{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g,sum);
			calc_count<=calc_count+1;
			mem_addr<=mem_addr+1;		
			sum<=w[15]+sha256_k[calc_count+1]+g;
		end
		else begin//first block 16-63
			mem_addr<=16;
			w[15]<=wtnew;
			sum<=w[15]+sha256_k[calc_count+1]+g;
			{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, sum);//needs to be changed, figure out what needs to be precomputed
			calc_count<=calc_count+1;
			if(calc_count>61)begin
				w[15]<=mem_read_data;
				mem_addr<=mem_addr+1;
				$display("wwww:%h",w[15]);
				sum<=w[15]+sha256_k[0]+g;
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
					a<=H0+a;
					b<=H1+b;
					c<=H2+c;						
					d<=H3+d;
					e<=H4+e;
					f<=H5+f;
					g<=H6+g;
					h<=H7+h;
					block<=1;
					calc_count<=0;
					//state<=COMPUTE;
					//mem_addr<=message_addr+16;
					state<=MIDDLE;
				end
			end
		end
	end	
	
	MIDDLE:begin
				mem_we<=0;
				w[15]<=mem_read_data;
				sum<=w[15]+sha256_k[calc_count+1]+g;
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, sum);
				calc_count<=calc_count+1;
				for(n=0;n<15;n++)begin
					w[n]<=w[n+1];
				end
				mem_addr<=mem_addr+1;
				if(calc_count==2)begin
					state<=COMPUTE;
					w[15]<=nonces;
					{Ma, Mb, Mc, Md, Me, Mf, Mg, Mh} <= sha256_op(a, b, c, d, e, f, g,sum);
				end
	end
	COMPUTE: begin
			/*if(calc_count<3)begin
				mem_we<=0;
				w[15]<=mem_read_data;
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, mem_read_data, sha256_k[calc_count]);
			$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, w15: %h, calc_count: %d, read_count:%h",state,a,b,c,d,e,f,g,h,w[15],calc_count-1,read_count);			
				calc_count<=calc_count+1;
				for(n=0;n<15;n++)begin
					w[n]<=w[n+1];
				end
				mem_addr<=message_addr+read_count;
				read_count<=read_count+1;
			end
			else if(calc_count==3)begin*/
			if(calc_count==3)begin
				w[15]<=32'h80000000;
				sum<=w[15]+sha256_k[calc_count+1]+g;
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g,sum);
				for(n=0;n<15;n++)begin
					w[n]<=w[n+1];
				end
				calc_count<=calc_count+1;
			end
			/*else if(calc_count==4)begin
				w[15]<=32'h80000000;
				sum<=w[15]+sha256_k[calc_count+1]+g;
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, sum);
				for(n=0;n<15;n++)begin
					w[n]<=w[n+1];
				end		
				calc_count<=calc_count+1;
			end*/
			else if(calc_count>3 & calc_count<14) begin
				w[15]<=32'h00000000;
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, sum);
				for(n=0;n<15;n++)begin
					w[n]<=w[n+1];
				end
				calc_count<=calc_count+1;
			end
			else if(calc_count==14)begin
					w[15]<=32'd640;
					for (int n = 0; n < 15; n++) begin
						w[n] <= w[n+1];
					end
					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g,sum);
					calc_count<=calc_count+1;
			end
			else if(calc_count>14 & calc_count<64)begin
				w[15]<=wtnew;
				for (int n = 0; n < 15; n++) begin
					w[n] <= w[n+1];
				end
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, sum);
				calc_count<=calc_count+1;
				
			end
			else if(calc_count==64)begin
				p3[0]<=H0+a;
				p3[1]<=H1+b;
				p3[2]<=H2+c;
				p3[3]<=H3+d;
				p3[4]<=H4+e;
				p3[5]<=H5+f;
				p3[6]<=H6+g;
				p3[7]<=H7+h;
				p3[8]=32'h80000000;
				p3[9]='h00000000;
				p3[10]='h00000000;
				p3[11]='h00000000;
				p3[12]='h00000000;
				p3[13]='h00000000;
				p3[14]='h00000000;
				p3[15]='d256;
				H0<= 'h6a09e667;
				H1<= 'hbb67ae85;
				H2<= 'h3c6ef372;
				H3<= 'ha54ff53a;
				H4<= 'h510e527f;
				H5<= 'h9b05688c;
				H6<= 'h1f83d9ab;
				H7<= 'h5be0cd19;
				a<= 'h6a09e667;
				b<= 'hbb67ae85;
				c<= 'h3c6ef372;
				d<= 'ha54ff53a;
				e<= 'h510e527f;
				f<= 'h9b05688c;
				g<= 'h1f83d9ab;
				h<= 'h5be0cd19;
				calc_count<=0;
				block<=2;
				state<=COMPUTE2;
			end

		end//last round load 
	COMPUTE2: begin
			w[15]<=p3[calc_count];
			for(n=0;n<15;n++)begin
				w[n]<=w[n+1];
			end
			if(calc_count<16)begin
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, sum);
				calc_count<=calc_count+1;
				
			end
			else begin
				w[15]<=wtnew;
				for (int n = 0; n < 15; n++) begin
					w[n] <= w[n+1];
				end				
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g,sum);

				calc_count<=calc_count+1;
				//state<=COMPUTE;
				if(calc_count>62)begin
					mem_addr<=mem_addr+1;
					if(calc_count==64)begin
						mem_we<=1;
						mem_addr<=output_addr+nonces;
						mem_write_data<=a+32'h6a09e667;
						state<=WRITE;
					end
				end
			end
		end
	
	
	WRITE: begin
	if(nonces!='h0000000F)begin
		mem_we<=0;
		mem_addr<=mem_addr+1;
		nonces<=nonces+1;
		//read_count<=18;
		calc_count<=0;
		block<=1;
		mem_addr<=17;
		H0<=FC0;
		H1<=FC1;
		H2<=FC2;						
		H3<=FC3;
		H4<=FC4;
		H5<=FC5;
		H6<=FC6;
		H7<=FC7;
		state<=COMPUTE;
		a<=Ma;
		b<=Mb;
		c<=Mc;
		d<=Md;
		e<=Me;
		f<=Mf;
		g<=Mg;
		h<=Mh;
		w[15]<='h159c048d;
		w[14]<='h8ace0246;
		w[13]<='h45670123;
		calc_count<=3;
	end
	else begin
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