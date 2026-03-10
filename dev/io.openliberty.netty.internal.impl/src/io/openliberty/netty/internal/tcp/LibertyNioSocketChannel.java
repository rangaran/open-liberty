package io.openliberty.netty.internal.tcp;

import java.nio.channels.SocketChannel;
import java.util.Optional;
import java.util.OptionalLong;

import io.netty.channel.Channel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.util.AttributeKey;
import io.openliberty.netty.internal.ConfigConstants;
import io.openliberty.netty.internal.tcp.SocketHandle;

public class LibertyNioSocketChannel extends NioSocketChannel{

    public final AttributeKey<SocketHandle> HANDLE_KEY = AttributeKey.valueOf("HandleKey");

    public LibertyNioSocketChannel(){
        super();
        installHandle();
    }

    public LibertyNioSocketChannel(SocketChannel socket){
        super(socket);
        installHandle();
    }

    public LibertyNioSocketChannel(Channel parent, SocketChannel socket){
        super(parent, socket);
        installHandle();
    }

    private void installHandle(){
        System.out.println("Installing socket handle");
        SocketChannel ch = javaChannel();
        SocketHandle handle = new SocketHandle(this, localAddress(), remoteAddress(),
                                                Optional.of(ch.socket()),
                                                Optional.of(ch),
                                                OptionalLong.empty(),
                                                "nio");

        System.out.println("Recorded socket is: " + handle.getJavaSocket());

        attr(HANDLE_KEY).set(handle);
    }    
}
