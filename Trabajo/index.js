const NodeRSA = require('node-rsa');
const path = require('path');
const util = require('util');
const fs = require('fs');
const directoryPath = path.join(__dirname, 'CarpetaDeLlaves');
const readline = require('readline').createInterface({
  input: process.stdin,
  output: process.stdout
});

// Hacer que fs.readdir retorne una promesa para poder usarlo con sintaxis async/await
const readFile = util.promisify(fs.readFile);
const writeFile = util.promisify(fs.writeFile);

let privateKeyString = null;
let publicKeyString = null;

async function main() {
  try {
    // Intenta leer los archivos .pem que tienen los keys en string
    privateKeyString = await readFile(directoryPath+'/privateKey.pem', 'utf8');
    publicKeyString = await readFile(directoryPath+'/publicKey.pem', 'utf8');
  } catch (e) {
    console.error('error: ', e);
  }
  // Checa si el private y public key se leyó bien del archivo en caso de que ya existiera, sino crea uno
  if (privateKeyString && publicKeyString){
    console.log('Ya existe el key');
    // se iinicializa key desde el archivo que ya existe
    const key = new NodeRSA(privateKeyString);
    enviarMensaje(key)
  } else {
    console.log('No existe el key y se crea un nuevo key');
    const key = new NodeRSA({b: 512});
    privateKeyString = key.exportKey('pkcs1-private-pem');
    publicKeyString = key.exportKey('pkcs1-public-pem');
    try{
      // Se crean los archivos
      await writeFile(directoryPath+'/privateKey.pem', privateKeyString);
      await writeFile(directoryPath+'/publicKey.pem', publicKeyString);
      enviarMensaje(key)
    } catch (e) {
      console.log('no se guardó alguna clave a un archivo :/ ', e);
    }
  }
}

// Esta funcion simula enviar un mensaje de servidor a cliente
function enviarMensaje(key){
  readline.question(`Escribe el mensaje que deseas enviar: `, (mensaje) => {
    const mensajeAEnviarEncriptado = key.encryptPrivate(mensaje);
    // Se envía el mensaje junto con el publicKey en string
    // Se envía a la función que lo desencripta con la llave publica
    // publicKeyString esta declarada globalmente
    desencriptarMensaje(mensajeAEnviarEncriptado, publicKeyString);
  });
}

// Esta función es como si estuviera corriendo en el cliente y recibiera un mensaje encriptado del servidor
function desencriptarMensaje(mensajeEncriptado, publicKey){
  console.log('Mensaje Encriptado: ', mensajeEncriptado);
  // Se genera el key para desencriptar basado en el string de publicKey que llegó junto con el mensaje
  const key = new NodeRSA(publicKey);
  // Desencripta el mensaje
  const mensajeDesencriptado = key.decryptPublic(mensajeEncriptado, 'utf8');
  console.log('Mensaje desencriptado: ', mensajeDesencriptado);
  // Contestamos con un mensaje encriptado con el publicKey
  readline.question(`Escribe una respuesta al mensaje: `, (mensaje) => {
    const mensajeAEnviar = mensaje;
    readline.close();
    // Encripta el mensaje con el publicKey
    const mensajeRespuestaEncriptado = key.encrypt(mensajeAEnviar, 'buffer', 'utf8');
    // Se envía a la función que desencripta la respuesta con la llave privada
    recibirRespuesta(mensajeRespuestaEncriptado);
  });
}

// Esta función es como si estuviera corriendo en el servidor y recibiera un mensaje encriptado del cliente
function recibirRespuesta(mensajeRespuestaEncriptado){
  console.log('en el recibir, mesnaje encriptado: ', mensajeRespuestaEncriptado);
  // Se usa la llave privada para desencriptar el mensjae que llego y se encriptó con la llave pública
  const key = new NodeRSA(privateKeyString);
  const respuesta = key.decrypt(mensajeRespuestaEncriptado, 'utf8');
  console.log('Respuesta desencriptada: ', respuesta);
}

main();

