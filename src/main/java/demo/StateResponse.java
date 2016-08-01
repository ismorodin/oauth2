package demo;

import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.io.Serializable;

/**
 * @author Ivan Smorodin
 * @since 02.08.2016
 */
@Data
@Builder
public class StateResponse implements Serializable {
    private String sid;
    private HttpStatus status;
    private String smsCode;
}
