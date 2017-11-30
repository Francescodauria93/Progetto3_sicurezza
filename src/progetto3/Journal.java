/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author gia
 */
public class Journal implements Serializable {
    
    List<byte []> byteListSH;
    List<byte []> byteListRH;

    public Journal() {
        
        this.byteListSH = new ArrayList<byte[]>();
        this.byteListRH = new ArrayList<byte[]>();
    }
    
    public void load(String path) throws ClassNotFoundException, IOException{
       
        ByteArrayInputStream bis = new ByteArrayInputStream(utility.loadFile(path));
        ObjectInput in = null;
        in = new ObjectInputStream(bis);
        Journal j = (Journal) in.readObject();
        this.byteListSH = j.getListSH();
        
    }
    

        
    public void save(String path ,String label) throws IOException{
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = new ObjectOutputStream(bos);
        out.writeObject(this);
        out.flush();
        byte[] byteClass = bos.toByteArray();
        out.close();
        
        utility.writeFile(path+"/"+label+".j",byteClass);
        
    }
    public List getListSH (){
        return this.byteListSH;
    }
    
      public List getListRH (){
        return this.byteListRH;
    }
    
    
    
}
