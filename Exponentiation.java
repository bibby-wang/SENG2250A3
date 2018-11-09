import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * ��Ҫ���ڼ��㳬�������������Ȼ��Գ��������ȡģ��
 * �������ϲ�ѯ������㷨����"�ɸ������㷨"��
 * @author ���Ŵ����
 */
public class Exponentiation {

    /**
     * ���������������Ȼ��Գ��������ȡģ
        (base ^ exponent) mod n
     * @param base
     * @param exponent
     * @param n
     * @return
     */
    public BigInteger expMode(BigInteger base, BigInteger exponent, BigInteger n){
        char[] binaryArray = new StringBuilder(exponent.toString(2)).reverse().toString().toCharArray() ;
        int r = binaryArray.length ;
        List<BigInteger> baseArray = new ArrayList<BigInteger>() ;

        BigInteger preBase = base ;
        baseArray.add(preBase);
        for(int i = 0 ; i < r - 1 ; i ++){
            BigInteger nextBase = preBase.multiply(preBase).mod(n) ;
            baseArray.add(nextBase) ;
            preBase = nextBase ;
        }
        BigInteger a_w_b = this.multi(baseArray.toArray(new BigInteger[baseArray.size()]), binaryArray) ;
        return a_w_b.mod(n) ;
    }


    private BigInteger multi(BigInteger[] array, char[] bin_array){
        BigInteger result = BigInteger.ONE ;
        for(int index = 0 ; index < array.length ; index ++){
            BigInteger a = array[index] ;
            if(bin_array[index] == '0'){
                continue ;
            }
            result = result.multiply(a) ;
        }
        return result ;
    }

}
