package io.openliberty.netty.internal.tcp;
import java.nio.channels.SocketChannel;
import java.util.List;

import io.netty.channel.socket.nio.NioServerSocketChannel;

public class LibertyNioServerSocketChannel extends NioServerSocketChannel{

    @Override
    protected int doReadMessages(List<Object> buf) throws Exception {
        SocketChannel ch = javaChannel().accept();
        try {
            if(ch != null){
                buf.add(new LibertyNioSocketChannel(this, ch));
                return 1;
            }
        } catch (Throwable t){
            //logger.warn("Failed to create a new channel from an accepted socket.", t);

            try {
                ch.close();
            } catch (Throwable t2){
                //logger.warn("Failed to close a socket.", t2);
            }
        }

        return 0;
    }
    
}
