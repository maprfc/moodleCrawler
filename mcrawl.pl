#!/usr/bin/perl
#
# Mario Arturo Perez Rangel
# Jose Luis Torres Rodriguez
# Version: 0.1
#
use warnings;
use strict;
use Term::ReadKey;
use MIME::Base64;
use Getopt::Long;
use IO::Socket::SSL;
use HTTP::Request;
use LWP::UserAgent;
use HTML::TreeBuilder;

my %params = (loop => 0);
my %opciones;
my %sslopts=();
#my %sslopts=(SSL_verify_mode => SSL_VERIFY_NONE,
#	     verify_hostname => 0,
#	     SSL_ca_path => IO::Socket::SSL::default_ca(),);

GetOptions (\%opciones, 'help|h', 'ip|s=s', 'dict|d=s', 'report|r',
	                'login|l=s', 'password|p=s', 'url=s',
	    );

if ($opciones{help}){
    muestraAyuda();
    exit (1);
}


procesaOpciones(\%opciones, \%params);
adjustParams(\%params, \%sslopts);

# Hacemos peticiones con el metodo HEAD hasta determinar si en la url proporcionada
# el servidor despacha moodle, o se redirecciona a un sitio con SSL. Tambien se detecta
# si el certificado del servidor es emitido por alguna CA valida. Si es autofirmado o
# presenta problemas saltamos la validacion del certificado
sub adjustParams {
    my ($p, $ssl) = @_;
    my ($ua, $req, $res);
    
    if ($p->{loop}++ > 6){  # Contamos el numero de veces que se ha llamado la funcion
	print "Demasiados intentos de ajustar los parametros de conexion.\n";
	exit (-1);
    }
    $ua = LWP::UserAgent->new(
	ssl_opts => $ssl,
	);

    $ua->agent('Mozilla/5.0');

    $req = HTTP::Request->new(HEAD => $params{url});
    $res = $ua->request($req);

    print $res->code, "\n";
    if ($res->code == 200) { # Todo bien
	return;
    } elsif ($res->code == 301 or $res->code == 302)  { # Redireccionar
	print $res->headers->{'location'}, "Se movio de lugar\n";
    } elsif ($res->code == 403) {
	print "No se tiene acceso a este recurso.\n";
	exit (-1);
    } elsif ($res->code == 500) {
	if ($res->status_line =~ /certificate verify failed/) {
	    $ssl->{SSL_verify_mode} = SSL_VERIFY_NONE;
	    $ssl->{verify_hostname} = 0;
	    adjustParams($p, $ssl);
	}
    }

#if ($res->is_success) {
#    print $res->as_string;
#    print $res->content();
#}
#if ($res->is_error) {
#    print $res->as_string();
#    if ($res->code() == 500) {
#	$sslopts{SSL_verify_mode} = SSL_VERIFY_NONE;
#	$sslopts{verify_hostname} = 0;
#	$sslopts{SSL_ca_path} = IO::Socket::SSL::default_ca();
#	$ua->ssl_opts (\%sslopts);
#
#	$res = $ua->request($req);
#	if ($res->is_success) {
#	    print $res->as_string();
#	}
#    }
#}
}
##
## Manejo de las opciones en linea de comandos.
## Recibe: dos hashes, uno con las opciones recibidas en linea de comandos y
## un segundo hash con las parametros a pasar a las funciones try_Basic, try_Digest y try_Forma
##
## Regresa el hash de parametros modificados
##
sub procesaOpciones {
    my ($op, $p) = @_;
    
    if ($op->{dict}) {
	my $nl = (stat $op->{dict})[3];
	$nl = 0 if (!$nl);
	if ($nl <= 0) {
	    print "No existe el archivo con el diccionario.\n";
	    exit(1);
	}
	$p->{dict} = $op->{dict};
    }
    if ($op->{ip}){
	 # Es una direccion ip valida?
	if ($op->{ip} =~ /^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$/) {
	    $p->{host} = $op->{ip};
	} else {
	    print "Debe proporcionar una direccion ip valida.\n";
	    exit (3);
	}
    }
    if ($op->{url}){
	# Desmenuza la url en schema, host, puerto y uri
	if ($op->{url} =~ m|^(https?)(://)([\w\d._-]+)(:\d+)?(/.*)$|) {
	    $p->{scheme} = $1;
	    $p->{host} = $3;
	    if ($4) {
		$p->{port} = $4;
		$p->{port} =~ s/^://;
	    }
	    $p->{uri} = $5;
	    $p->{url} = $op->{url};
	} else {
	    print "La url no tiene el formato requerido.\n";
	    print "Debe ser de la forma:\n";
	    print "                      http(s)://host(:puerto)/<ruta del recurso>\n";
	    print "Ejemplo:\n";
	    print "         https:///my.moodle.com/login.php\n";
	    exit (4);
	}
    }
    if($op->{report}) {
	$p->{report} = 1;
    }
    if ($op->{login} and $op->{password}) {
	if ($op->{login} =~ /^(?:[\w\d._-]+@)?[\w\d._-]+$/) {
	    $p->{login} = $op->{login};
	} else {
	    print "El login no tiene un formato valido.\n";
	    exit (2);
	}
	if ($op->{password} =~ /^[\w\d._,;:]+$/) {
	    $p->{password} = $op->{password};
	} else {
	    print "No parece ser un password valido\n";
	    exit (3);
	}
    } elsif ($op->{login} and !$op->{password}) {
	if ($op->{login} =~ /^(?:[\w\d._-]+@)?[\w\d._-]+$/) {
	    $p->{login} = $op->{login};

	    ReadMode ('noecho');
	    print "Password: ";
	    chomp($op->{password} = <STDIN>);
	    ReadMode ('restore');
	    if ($op->{password} eq '') {
		print "No puede usar un password vacio.\n";
		exit (4);
	    }
	    if ( !($op->{password} =~ /[\w\d._,;:]+/) ) {
		print "No parece ser un password valido.\n";
		exit (5);
	    }
	}
    } elsif ( $op->{password} and !$op->{login} ){
	print "Necesita un login para ese password\n";
	exit (6);
    }
#    if ($op->{ufile}){
#	if ((stat($op->{ufile}))[3] > 0) { # El archivo existe si el numero de ligas en el sistema de archivo es mayor a cero
#	    $p->{ufile} = $op->{ufile};
#	} else {                           # No existe asi que usamos uno por defecto
#	    $p->{ufile} = 'usernames.txt';
#	}
#    }
#    if ($op->{pfile}){
#	if ((stat($op->{pfile}))[3] > 0) { # El archivo existe si el numero de ligas en el sistema de archivo es mayor a cero
#	    $p->{pfile} = $op->{pfile};
#	} else {                           # No existe asi que usamos uno por defecto.
#	    $p->{pfile} = 'passwords.txt';
#	}
#    }
    return $p;
}

##
## muestraAyuda muestra al usuario como se debe usar este programa.
##
sub muestraAyuda {
    print "$0 implementa dos tipos de ataque: fuerza bruta y de diccionario, contra un objetivo determinado.\n\n";
    print "La forma de usarlo es:\n";
    print "  $0 [--help|-h] [--http|--https] [--basic|-b|--digest|-d] \n";
    print ' 'x (length($0)+3), "--host <nombre de host>|--ip <ip>  [[--puerto|-p] <puerto>] \n";
    print ' 'x (length($0)+3), "--uri <uri> [--usuario <usuario>] [--ufile <archivo>] [--pfile <archivo>]  \n\n";
    print "Donde:\n";
    print "--help o -h\t Muestra esta ayuda\n";
    print "-http\t\t Implica hacer conexiones con el protocolo HTTP.\n";
    print "-https\t\t Implican hacer conexiones con el protocolo HTTP median SSL/TLS.\n";
    print "--basic o -b\t Dirige el ataque usando el metodo de autenticacion BASIC\n";
    print "--digest o -d\t Dirige el ataque usando el metodo de autenticacion DIGEST\n";
    print "--host\t\t Nombre de dominio del objetivo\n";
    print "--ip\t\t Direccion ip del objetivo\n";
    print "--puerto o -p\t El puerto TCP del objetivo\n";
    print "--uri o -u\t La ruta dentro del recurso dentro del objetivo, ej.: /webdav/\n";
    print "--usuario\t El nombre de usuario a usar en el ataque.\n";
    print "--ufile\t\t Nombre de un archivo con nombres de usuario, uno por linea.\n";
    print "--pfile\t\t Nombre de un archivo con contrasenias de usuario, uno por linea.\n\n";
    print "Los parametros --host y --uri no se pueden predeterminar por lo que es obligatorio su aparicion en la linea de comandos.\n\n";
    print "De manera predeterminada se usa el protocolo http en el puerto 80.\n\n";
    print "Los parametros --host e --ip son excluyentes, no pueden ir ambos en la misma linea de comandos.\n\n";
    print "Todos los demas parametros son opcionales.\n\n";
}

