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

import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SniHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.DomainWildcardMappingBuilder;
import io.netty.util.Mapping;
import reactor.netty.NettyPipeline;
import reactor.util.annotation.Nullable;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * An {@link SniProvider} to configure the channel pipeline in order to support server SNI
 *
 * @author Violeta Georgieva
 * @since 1.0.0
 */
public final class SniProvider {

	public interface DefaultSslProviderSpec {

		/**
		 * The {@link SslProvider} builder for building the default {@link SslProvider}.
		 *
		 * @param sslProviderBuilder the {@link SslProvider} builder for building the default {@link SslProvider}
		 * @return {@literal this}
		 */
		DomainNameMappingSpec sslProvider(Consumer<? super SslProvider.SslContextSpec> sslProviderBuilder);

		/**
		 * The default {@link SslProvider}.
		 *
		 * @param sslProvider the default {@link SslProvider}
		 * @return {@literal this}
		 */
		DomainNameMappingSpec sslProvider(SslProvider sslProvider);
	}

	public interface DomainNameMappingSpec {

		/**
		 * Adds a mapping for the given domain name to an {@link SslProvider} builder.
		 * If a mapping already exists, it will be overridden.
		 *
		 * @param domainName the domain name, it may contain wildcard
		 * @param sslProviderBuilder an {@link SslProvider} builder for building the {@link SslProvider}
		 * @return {@literal this}
		 */
		DomainNameMappingSpec add(String domainName, Consumer<? super SslProvider.SslContextSpec> sslProviderBuilder);

		/**
		 * Adds the provided mappings of domain names to {@link SslProvider} builders to the existing mappings.
		 * If a mapping already exists, it will be overridden.
		 *
		 * @param confPerDomainName mappings of domain names to {@link SslProvider} builders
		 * @return {@literal this}
		 */
		DomainNameMappingSpec addAll(Map<String, Consumer<? super SslProvider.SslContextSpec>> confPerDomainName);

		/**
		 * Builds a new SniProvider
		 *
		 * @return a new SniProvider
		 */
		SniProvider build();

		/**
		 * Sets the provided mappings of domain names to {@link SslProvider} builders.
		 * The existing mappings will be removed.
		 *
		 * @param confPerDomainName mappings of domain names to {@link SslProvider} builders
		 * @return {@literal this}
		 */
		DomainNameMappingSpec setAll(Map<String, Consumer<? super SslProvider.SslContextSpec>> confPerDomainName);
	}

	/**
	 * Creates a builder for {@link SniProvider}
	 *
	 * @return a new {@link SniProvider} builder
	 */
	public static SniProvider.DefaultSslProviderSpec builder() {
		return new SniProvider.Build();
	}

	/**
	 * Creates a new {@link SniProvider} where every {@link SslProvider} in the mappings is updated with the
	 * provided type.
	 *
	 * @param provider original {@link SniProvider}
	 * @param type default configuration that will be applied to every {@link SslProvider} in the mappings
	 * @return a new {@link SniProvider} with updated type
	 */
	public static SniProvider updateAllSslProviderConfiguration(SniProvider provider, SslProvider.DefaultConfigurationType type) {
		Objects.requireNonNull(provider, "provider");
		Objects.requireNonNull(type, "type");
		return new SniProvider(provider, type);
	}

	/**
	 * Adds configured {@link SniHandler} to the channel pipeline.
	 *
	 * @param channel the channel
	 * @param sslDebug if true SSL debugging on the server side will be enabled
	 */
	public void addSniHandler(Channel channel, boolean sslDebug) {
		ChannelPipeline pipeline = channel.pipeline();
		pipeline.addFirst(NettyPipeline.SslHandler, newSniHandler());

		if (pipeline.get(NettyPipeline.LoggingHandler) != null) {
			pipeline.addAfter(NettyPipeline.LoggingHandler, NettyPipeline.SslReader, new SslProvider.SslReadHandler());
			if (sslDebug) {
				pipeline.addBefore(NettyPipeline.SslHandler,
						NettyPipeline.SslLoggingHandler,
						new LoggingHandler("reactor.netty.tcp.ssl"));
			}

		}
		else {
			pipeline.addAfter(NettyPipeline.SslHandler, NettyPipeline.SslReader, new SslProvider.SslReadHandler());
		}
	}

	/**
	 * Returns the default configuration that is applied to every {@link SslProvider} in the mappings.
	 *
	 * @return the default configuration that is applied to every {@link SslProvider} in the mappings
	 */
	@Nullable
	public SslProvider.DefaultConfigurationType defaultConfigurationType() {
		return defaultConfigurationType;
	}

	/**
	 * Returns a {@link SslProvider} that will be applied in case no mapping for a given domain name.
	 *
	 * @return a {@link SslProvider} that will be applied in case no mapping for a given domain name
	 */
	public SslProvider defaultSslProvider() {
		return defaultSslProvider;
	}

	final Map<String, SslProvider> confPerDomainName;
	final SslProvider.DefaultConfigurationType defaultConfigurationType;
	final SslProvider defaultSslProvider;

	SniProvider(Build build) {
		this.confPerDomainName = build.confPerDomainName;
		this.defaultConfigurationType = null;
		this.defaultSslProvider = build.defaultSslProvider;
	}

	SniProvider(SniProvider from, SslProvider.DefaultConfigurationType type) {
		this.confPerDomainName = new HashMap<>();
		from.confPerDomainName.forEach((s, sslProvider) ->
				this.confPerDomainName.put(s, SslProvider.updateDefaultConfiguration(sslProvider, type)));
		this.defaultConfigurationType = type;
		this.defaultSslProvider = SslProvider.updateDefaultConfiguration(from.defaultSslProvider, type);
	}

	SniHandler newSniHandler() {
		DomainWildcardMappingBuilder<SslContext> mappingsContextBuilder =
				new DomainWildcardMappingBuilder<>(defaultSslProvider.getSslContext());
		confPerDomainName.forEach((s, sslProvider) -> mappingsContextBuilder.add(s, sslProvider.getSslContext()));
		DomainWildcardMappingBuilder<SslProvider> mappingsSslProviderBuilder =
				new DomainWildcardMappingBuilder<>(defaultSslProvider);
		confPerDomainName.forEach(mappingsSslProviderBuilder::add);
		return new AdvancedSniHandler(mappingsSslProviderBuilder.build(), defaultSslProvider, mappingsContextBuilder.build());
	}

	static final class AdvancedSniHandler extends SniHandler {

		final Mapping<? super String, ? extends SslProvider> confPerDomainName;
		final SslProvider defaultSslProvider;

		AdvancedSniHandler(
				Mapping<? super String, ? extends SslProvider> confPerDomainName,
				SslProvider defaultSslProvider,
				Mapping<? super String, ? extends SslContext> mappings) {
			super(mappings);
			this.confPerDomainName = confPerDomainName;
			this.defaultSslProvider = defaultSslProvider;
		}

		@Override
		protected SslHandler newSslHandler(SslContext context, ByteBufAllocator allocator) {
			SslHandler sslHandler = super.newSslHandler(context, allocator);
			String hostName = hostname();
			if (hostName == null) {
				defaultSslProvider.configure(sslHandler);
			}
			else {
				confPerDomainName.map(hostname()).configure(sslHandler);
			}
			return sslHandler;
		}
	}

	static final class Build implements DefaultSslProviderSpec, DomainNameMappingSpec {

		final Map<String, SslProvider> confPerDomainName = new HashMap<>();
		SslProvider defaultSslProvider;

		@Override
		public DomainNameMappingSpec sslProvider(Consumer<? super SslProvider.SslContextSpec> sslProviderBuilder) {
			Objects.requireNonNull(sslProviderBuilder, "sslProviderBuilder");
			SslProvider.SslContextSpec builder = SslProvider.builder();
			sslProviderBuilder.accept(builder);
			this.defaultSslProvider = ((SslProvider.Builder) builder).build();
			return this;
		}

		@Override
		public DomainNameMappingSpec sslProvider(SslProvider sslProvider) {
			this.defaultSslProvider = Objects.requireNonNull(sslProvider, "sslProvider");
			return this;
		}

		@Override
		public DomainNameMappingSpec add(String domainName, Consumer<? super SslProvider.SslContextSpec> sslProviderBuilder) {
			addInternal(domainName, sslProviderBuilder);
			return this;
		}

		@Override
		public DomainNameMappingSpec addAll(Map<String, Consumer<? super SslProvider.SslContextSpec>> confPerDomainName) {
			Objects.requireNonNull(confPerDomainName);
			confPerDomainName.forEach(this::addInternal);
			return this;
		}

		@Override
		public DomainNameMappingSpec setAll(Map<String, Consumer<? super SslProvider.SslContextSpec>> confPerDomainName) {
			Objects.requireNonNull(confPerDomainName);
			this.confPerDomainName.clear();
			confPerDomainName.forEach(this::addInternal);
			return this;
		}

		@Override
		public SniProvider build() {
			return new SniProvider(this);
		}

		void addInternal(String domainName, Consumer<? super SslProvider.SslContextSpec> sslProviderBuilder) {
			Objects.requireNonNull(domainName, "domainName");
			Objects.requireNonNull(sslProviderBuilder, "sslProviderBuilder");
			SslProvider.SslContextSpec builder = SslProvider.builder();
			sslProviderBuilder.accept(builder);
			confPerDomainName.put(domainName, ((SslProvider.Builder) builder).build());
		}
	}
}
