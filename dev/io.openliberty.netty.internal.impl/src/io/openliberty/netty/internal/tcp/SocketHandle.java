package io.openliberty.netty.internal.tcp;

import java.net.Socket;
import java.net.SocketAddress;
import io.netty.channel.Channel;
import java.nio.channels.SocketChannel;
import java.util.Optional;
import java.util.OptionalLong;

public class SocketHandle {

    private final Channel channel;
    private final SocketAddress localAddress;
    private final SocketAddress remoteAddress;
    private final Optional<Socket> javaSocket;
    private final Optional <SocketChannel> javaSocketChannel;
    private final OptionalLong nativeFD;
    private final String commClass;

    public SocketHandle(Channel channel, 
                            SocketAddress local,
                            SocketAddress remote,
                            Optional<Socket> javaSocket,
                            Optional<SocketChannel> javaSocketChannel,
                            OptionalLong nativeFD,
                            String commClass){
    
        this.channel = channel;
        this.localAddress = local;
        this.remoteAddress = remote;
        this.javaSocket = javaSocket;
        this.javaSocketChannel = javaSocketChannel;
        this.nativeFD = nativeFD;
        this.commClass = commClass;
    }

    public Optional<Socket> getJavaSocket(){
        return javaSocket;
    }
    
    
}
