/*
 * Copyright (c) 2011-Present VMware, Inc. or its affiliates, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reactor.netty.tcp;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.util.DomainWildcardMappingBuilder;
import io.netty.util.Mapping;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Violeta Georgieva
 */
public class SniProviderTest {
	static SelfSignedCertificate defaultCert;
	static SelfSignedCertificate localhostCert;
	static SelfSignedCertificate anotherCert;

	SniProvider.DefaultSslProviderSpec builder;
	SslContext defaultSslContext;
	SslContext localhostSslContext;
	SslContext anotherSslContext;

	@BeforeClass
	public static void createSelfSignedCertificate() throws CertificateException {
		defaultCert = new SelfSignedCertificate("default");
		localhostCert = new SelfSignedCertificate("localhost");
		anotherCert = new SelfSignedCertificate("another");
	}

	@Before
	public void setUp() throws Exception {
		builder = SniProvider.builder();

		SslContextBuilder defaultSslContextBuilder =
				SslContextBuilder.forServer(defaultCert.certificate(), defaultCert.privateKey());
		defaultSslContext = defaultSslContextBuilder.build();

		SslContextBuilder localhostSslContextBuilder =
				SslContextBuilder.forServer(localhostCert.certificate(), localhostCert.privateKey());
		localhostSslContext = localhostSslContextBuilder.build();

		SslContextBuilder anotherSslContextBuilder =
				SslContextBuilder.forServer(anotherCert.certificate(), anotherCert.privateKey());
		anotherSslContext = anotherSslContextBuilder.build();
	}

	@Test
	public void testDefaultSslProvider() {
		SniProvider.DomainNameMappingSpec mappingsSpec = builder.sslProvider(spec -> spec.sslContext(defaultSslContext));

		SniProvider provider = mappingsSpec.build();
		assertThat(mappings(provider).map("localhost")).isSameAs(defaultSslContext);
		assertThat(mappings(provider).map("another")).isSameAs(defaultSslContext);

		provider = mappingsSpec.add("localhost", spec -> spec.sslContext(localhostSslContext)).build();
		assertThat(mappings(provider).map("localhost")).isSameAs(localhostSslContext);
		assertThat(mappings(provider).map("another")).isSameAs(defaultSslContext);
	}

	@Test
	public void testDefaultSslProviderBadValues() {
		assertThatExceptionOfType(NullPointerException.class)
				.isThrownBy(() -> builder.sslProvider((Consumer<? super SslProvider.SslContextSpec>) null));

		assertThatExceptionOfType(NullPointerException.class)
				.isThrownBy(() -> builder.sslProvider((SslProvider) null));
	}

	@Test
	public void testAdd() {
		SniProvider.DomainNameMappingSpec mappingsSpec =
				builder.sslProvider(spec -> spec.sslContext(defaultSslContext))
				       .add("localhost", spec -> spec.sslContext(localhostSslContext));

		SniProvider provider = mappingsSpec.build();
		assertThat(mappings(provider).map("localhost")).isSameAs(localhostSslContext);

		provider = mappingsSpec.add("localhost", spec -> spec.sslContext(anotherSslContext)).build();
		assertThat(mappings(provider).map("localhost")).isSameAs(anotherSslContext);
	}

	@Test
	public void testAddBadValues() {
		assertThatExceptionOfType(NullPointerException.class)
				.isThrownBy(() -> builder.sslProvider(spec -> spec.sslContext(defaultSslContext))
						.add(null, spec -> spec.sslContext(localhostSslContext)));

		assertThatExceptionOfType(NullPointerException.class)
				.isThrownBy(() -> builder.sslProvider(spec -> spec.sslContext(defaultSslContext))
						.add("localhost", null));
	}

	@Test
	public void testAddAll() {
		Map<String, Consumer<? super SslProvider.SslContextSpec>> map = new HashMap<>();
		map.put("localhost", spec -> spec.sslContext(localhostSslContext));

		SniProvider.DomainNameMappingSpec mappingsSpec =
				builder.sslProvider(spec -> spec.sslContext(defaultSslContext))
				       .addAll(map);

		SniProvider provider = mappingsSpec.build();
		assertThat(mappings(provider).map("localhost")).isSameAs(localhostSslContext);

		map.put("another", spec -> spec.sslContext(anotherSslContext));

		provider = mappingsSpec.addAll(map).build();
		assertThat(mappings(provider).map("localhost")).isSameAs(localhostSslContext);
		assertThat(mappings(provider).map("another")).isSameAs(anotherSslContext);
	}

	@Test
	public void testAddAllBadValues() {
		assertThatExceptionOfType(NullPointerException.class)
				.isThrownBy(() -> builder.sslProvider(spec -> spec.sslContext(defaultSslContext)).addAll(null));
	}

	@Test
	public void testSetAll() {
		Map<String, Consumer<? super SslProvider.SslContextSpec>> map = new HashMap<>();
		map.put("localhost", spec -> spec.sslContext(localhostSslContext));

		SniProvider.DomainNameMappingSpec mappingsSpec =
				builder.sslProvider(spec -> spec.sslContext(defaultSslContext))
				       .setAll(map);

		SniProvider provider = mappingsSpec.build();
		assertThat(mappings(provider).map("localhost")).isSameAs(localhostSslContext);

		map.clear();
		map.put("another", spec -> spec.sslContext(anotherSslContext));

		provider = mappingsSpec.setAll(map).build();
		assertThat(mappings(provider).map("localhost")).isSameAs(defaultSslContext);
		assertThat(mappings(provider).map("another")).isSameAs(anotherSslContext);
	}

	@Test
	public void testSetAllBadValues() {
		assertThatExceptionOfType(NullPointerException.class)
				.isThrownBy(() -> builder.sslProvider(spec -> spec.sslContext(defaultSslContext)).setAll(null));
	}

	static Mapping<String, SslContext> mappings(SniProvider provider) {
		DomainWildcardMappingBuilder<SslContext> mappingsBuilder =
				new DomainWildcardMappingBuilder<>(provider.defaultSslProvider.getSslContext());
		provider.confPerDomainName.forEach((s, sslProvider) -> mappingsBuilder.add(s, sslProvider.getSslContext()));
		return mappingsBuilder.build();
	}
}
