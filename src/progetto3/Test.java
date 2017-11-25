/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package progetto3;

import java.io.IOException;

/**
 *
 * @author gia
 */
public class Test {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {
        TSA a  = new TSA();
        if("ciao2.hv".compareTo("ciao1.hv")==1){
        System.out.println("prima maggiore della seconda");
        }else{
            System.out.println("seconda maggiore della prima");
        }
    }
    
}
