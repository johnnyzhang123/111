module bitcoin_hash (input logic clk, reset_n, start,
 input logic [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);
 // SHA256 K constants
 parameter int k[0:63] = '{
 32'h428a2f98,32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
 32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
 32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
 32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
 32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
 32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
 32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
 32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};
logic [31:0] w[16],H[8],T[8],inter[16];
logic [31:0] a,b,c,d,e,f,g,h,sum;
//logic [31:0] inter[16];
logic [6:0] count;
logic [5:0]	nonces;
logic [4:0]n;
enum logic [3:0] {IDLE,READ1,READ2,READ3,COMPUTE0,COMPUTE1,REST,REST2,COMPUTE2,REST3,REST4,COMPUTE3,WRITE,BACK1,BACK2,DONE} state;
assign mem_clk=clk;
//function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w, k);
//assign sha256_out=sha256_op(a....sum);
//(a,--h)<=sha256_out
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g,sum);
logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
 ch = (e & f) ^ ((~e) & g);
 t1=S1+ch+sum;
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

//start.
always_ff @(posedge clk, negedge reset_n) begin
	$display("state: %h, a: %h, b: %h, c: %h, d: %h, e: %h, f: %h, g: %h, h: %h, wt: %h, count: %d,mem_read_data: %h, mem_addr:%h, sum:%h ",state,a,b,c,d,e,f,g,h,w[15],count-1,mem_read_data,mem_addr,sum);
	if (!reset_n) begin
		state <= IDLE;
		done<=0;
		count<=0;
		nonces<='h00000000;
	end 
	else case(state)
	
	IDLE:
		if(start) begin
			mem_we <= 0;
		   mem_addr <= message_addr;
			H[0]<=32'h6a09e667;
         H[1]<=32'hbb67ae85;
         H[2]<=32'h3c6ef372;
         H[3]<=32'ha54ff53a;
         H[4]<=32'h510e527f;
         H[5]<=32'h9b05688c;
         H[6]<=32'h1f83d9ab;
         H[7]<=32'h5be0cd19; //can delete
			a<='h6a09e667;
			b<='hbb67ae85;
			c<='h3c6ef372;
			d<='ha54ff53a;
			e<='h510e527f;
			f<='h9b05688c;
			g<='h1f83d9ab;
			h<='h5be0cd19;
			state <= READ1;
	end
	
	READ1: begin
		state <= READ2;				
		mem_addr <= mem_addr + 1;	
	end
	
	READ2: begin
		w[15]<= mem_read_data;
		mem_addr<=mem_addr+1;
		for (int n=0;n<15;n++) w[n]<=w[n+1]; //make room for w[15]
		state<= READ3;
	end
	READ3: begin
		w[15]<=mem_read_data;
		for (int n=0;n<15;n++) w[n]<=w[n+1];
		mem_addr<=mem_addr+1;
		sum<=w[15]+k[count]+'h5be0cd19;//k[count] use constant
		count<=count+1;
		state<=COMPUTE0;
	end
	
	COMPUTE0: begin
		for(int n=0; n<15;n++) w[n]<=w[n+1];
		sum<=w[15]+k[count]+g;
		{a,b,c,d,e,f,g,h}<=sha256_op(a,b,c,d,e,f,g,sum);
		count<=count+1;
		w[15]<=mem_read_data;
		mem_addr<=mem_addr+1;
		if(count==15)begin
			w[15]<=wtnew;
			mem_addr<=17;
			state<=COMPUTE1;
			inter[0]<=mem_read_data;
		end
	end
	COMPUTE1:begin
		for(int n=0; n<15;n++) w[n]<=w[n+1];
		{a,b,c,d,e,f,g,h}<=sha256_op(a,b,c,d,e,f,g,sum);
		count<=count+1;
		if (count<65) begin
				w[15]<=wtnew;
				sum<=w[15]+k[count]+g;
				if(count==64)begin
					w[15]<=inter[0];
					mem_addr<=mem_addr+1;
				end
		end
		else begin
			w[15]<=mem_read_data;
			mem_addr<=mem_addr+1;
			sum<=w[15]+k[0]+H[7]+h;
			count<=1;
			T[0]<=H[0]+a;
			T[1]<=H[1]+b;
			T[2]<=H[2]+c;
			T[3]<=H[3]+d;
			T[4]<=H[4]+e;
			T[5]<=H[5]+f;
			T[6]<=H[6]+g;
			T[7]<=H[7]+h;
			H[0]<=H[0]+a;
			H[1]<=H[1]+b;
			H[2]<=H[2]+c;
			H[3]<=H[3]+d;
			H[4]<=H[4]+e;
			H[5]<=H[5]+f;
			H[6]<=H[6]+g;
			H[7]<=H[7]+h;
			g<=H[6]+g;
			state<=REST;
		end
	end
	//begin second block
	REST: begin
		{a,b,c,d,e,f,g,h}<=sha256_op(H[0],H[1],H[2],H[3],H[4],H[5],H[6],sum);
		w[15]<=mem_read_data;
		for (int n=0;n<15;n++) w[n]<=w[n+1]; //make room again for w[15]
		sum<=w[15]+k[count]+g;
		count<=count+1;
		mem_addr<=mem_addr+1;
		state<= REST2;
	end
	
	REST2: begin
		{a,b,c,d,e,f,g,h}<=sha256_op(a,b,c,d,e,f,g,sum);
		w[15]<=nonces;
		for (int n=0;n<15;n++) w[n]<=w[n+1]; //make room again for w[15]
		mem_addr<=mem_addr+1;
		sum<=w[15]+k[count]+g;  //think about which value
		count<=count+1;
		state<= COMPUTE2;
	end
		
	COMPUTE2: begin
	if(count<65) begin
		sum<=w[15]+k[count]+g;
		{a,b,c,d,e,f,g,h}<=sha256_op(a,b,c,d,e,f,g,sum);
		for (int n=0;n<15;n++) w[n]<=w[n+1]; //make room again for w[15]
		count<=count+1;
		if(count==3) begin
			w[15]<= 32'h80000000;
		end
		else if(count<14 && count>3) begin
			w[15]<= 32'h00000000;
		end
		else if(count==14) begin
			w[15]<=32'd640;
		end
		else begin
			w[15]<=wtnew;
		end
	end
	else begin //count>=64
		w[15]<=H[0]+a;		
		for (int n=0;n<15;n++) w[n]<=w[n+1];
		inter[1]<=H[1]+b;
		inter[2]<=H[2]+c;
		inter[3]<=H[3]+d;
		inter[4]<=H[4]+e;
		inter[5]<=H[5]+f;
		inter[6]<=H[6]+g;	
		inter[7]<=H[7]+h;		
		inter[8]<=32'h80000000;
		inter[9]<=32'h00000000;
		inter[10]<=32'h00000000;
		inter[11]<=32'h00000000;
		inter[12]<=32'h00000000;
		inter[13]<=32'h00000000;
		inter[14]<=32'h00000000;
		inter[15]<='d256;
		H[0]<=32'h6a09e667;
      H[1]<=32'hbb67ae85;
      H[2]<=32'h3c6ef372;
      H[3]<=32'ha54ff53a;
		H[4]<=32'h510e527f;
		H[5]<=32'h9b05688c;
		H[6]<=32'h1f83d9ab;
		H[7]<=32'h5be0cd19;
		state<=REST3;
		count<=1; //reinitialize count
	end
end
	
	REST3: begin
		for(int n=0;n<15;n++) w[n]<=w[n+1];
		w[15]<=inter[count];
		sum<=w[15]+k[0]+'h5be0cd19;
		count<=count+1;
		state<=REST4;
	end
	REST4:begin
		{a,b,c,d,e,f,g,h}<=sha256_op('h6a09e667,'hbb67ae85,'h3c6ef372,'ha54ff53a,'h510e527f,'h9b05688c,'h1f83d9ab,sum);
		for(int n=0;n<15;n++) w[n]<=w[n+1];
		w[15]<=inter[count];
		sum<=w[15]+k[count]+'h1f83d9ab;
		count<=count+1;
		state<=COMPUTE3;
	end
	
	COMPUTE3: begin
	if(count<64) begin
		for (int n=0;n<15;n++) w[n]<=w[n+1];
		sum<=w[15]+k[count]+g;
		{a,b,c,d,e,f,g,h}<=sha256_op(a,b,c,d,e,f,g,sum);
		count<=count+1;
		if(count<16) begin
			w[15]<=inter[count];
		end
		else begin
			w[15]<=wtnew;
		end
	end
	
	else begin 
		mem_addr<=output_addr+nonces;
		mem_we<=1;
		state<=WRITE;
	end
	end

	WRITE: begin
		mem_write_data<=a+32'h6a09e667;
		state<=BACK1;	
	end
	
	BACK1: begin
		mem_we<=0;
		mem_addr<=message_addr+16;
		if(nonces<16) begin    // IMPORTANT: figure out what the number is here
			nonces<=nonces+1;
			state<=BACK2;
		end
		else begin
			state<=IDLE;
			done<=1;
		end
		for(int n=0;n<8;n++) H[n]<=T[n];
	end
	
	BACK2: begin
		mem_addr<=mem_addr+1;
		state<=REST;
	
	end
	
	endcase
	end
	endmodule
