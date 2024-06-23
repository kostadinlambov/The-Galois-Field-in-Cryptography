package com.klambov.aesencryption.crypt;

import java.util.Objects;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.style.ToStringCreator;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "lottaa.crypt")
public class LottaaCryptConfigProperties {

  private String key;

  public String getKey() {
    return key;
  }

  public void setKey(String key) {
    this.key = key;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof LottaaCryptConfigProperties)) {
      return false;
    }
    LottaaCryptConfigProperties that = (LottaaCryptConfigProperties) o;
    return getKey().equals(that.getKey());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getKey());
  }

  @Override
  public String toString() {
    return new ToStringCreator(this)
        .append("key", key)
        .toString();
  }
}
